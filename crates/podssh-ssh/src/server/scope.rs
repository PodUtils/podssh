//! Each pty child of `podssh serve` in a transient scope of its own where
//! systemd is there (T-122), as sshd moves each session out of its service:
//! a stop of serve's unit then leaves each user's shell, and its memory
//! counts against the scope, not against serve.
//!
//! No systemd is assumed. A probe at serve's start finds it (systemd is the
//! service manager, `busctl` is on `PATH`, and the user's manager answers
//! within [`PROBE_WAIT`]); else each child starts as before, and one line
//! says so. With it, each child is held between its fork and its exec until
//! the user's manager has moved it into `podssh-serve-PID-N.scope` by
//! `StartTransientUnit`, so the scope holds the whole tree of the session.
//! A move that fails or takes too long lets the child go on where it is,
//! with one line: no session fails because systemd is absent or slow.
//!
//! Lost to this: `systemd-run --user --scope -- SHELL`, which execs the
//! shell itself. Its failure would be the session's (its words on the
//! user's pty, then status 1), and it cannot give a login shell its dash.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The longest that the user's manager may take to answer the probe.
pub const PROBE_WAIT: Duration = Duration::from_secs(2);

/// The longest that the call of one move may take.
pub const CALL_WAIT: Duration = Duration::from_secs(2);

/// After the call, how long the child may take to show in its scope.
pub const SETTLE: Duration = Duration::from_secs(1);

/// systemd is the service manager where this is a directory (sd_booted).
pub const BOOTED: &str = "/run/systemd/system";

/// The program that asks the user's manager for each scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub busctl: PathBuf,
}

/// What a probe's program gave: its stdout when it ran (whatever its exit
/// status), or why it did not.
pub type Ran = Result<String, String>;

/// The probe of this host: [`probe_with`] with the real file system, `PATH`
/// and programs, each within [`PROBE_WAIT`].
pub fn probe() -> Result<Tool, String> {
    if !cfg!(target_os = "linux") {
        return Err("not Linux: systemd is Linux's".into());
    }
    probe_with(Path::new(BOOTED), std::env::var_os("PATH").as_deref(), &|program, args| {
        pod_core::process::run_bounded(program, args, None, PROBE_WAIT)
            .map(|ran| ran.stdout)
            .map_err(|e| format!("{program}: {e}"))
    })
}

/// The probe with each part given: systemd is the service manager
/// (`booted` is a directory), `busctl` and `systemctl` are on `path`, and
/// `systemctl --user is-system-running` says that the user's manager runs
/// (`running` or `degraded`: a failed unit leaves it able to make scopes).
/// `Err` is the reason for the line of the start.
pub fn probe_with(booted: &Path, path: Option<&OsStr>, run: &dyn Fn(&str, &[&str]) -> Ran) -> Result<Tool, String> {
    if !std::fs::symlink_metadata(booted).is_ok_and(|m| m.is_dir()) {
        return Err(format!("systemd is not this host's service manager (no {})", booted.display()));
    }
    let busctl = on_path(path, "busctl").ok_or("no busctl on PATH")?;
    let systemctl = on_path(path, "systemctl").ok_or("no systemctl on PATH")?;
    let systemctl = systemctl.to_str().ok_or("the path of systemctl is not UTF-8")?;
    let said = run(systemctl, &["--user", "is-system-running"])?;
    let state = said.lines().next().unwrap_or("").trim();
    match state {
        "running" | "degraded" => Ok(Tool { busctl }),
        "" => Err("the user's manager said nothing (systemctl --user is-system-running)".into()),
        other => Err(format!("the user's manager is {other:?} (systemctl --user is-system-running)")),
    }
}

/// The first regular file named `name` that this user may run, in the
/// absolute directories of `path`.
pub fn on_path(path: Option<&OsStr>, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path?).filter(|dir| dir.is_absolute()).map(|dir| dir.join(name)).find(|file| runnable(file))
}

#[cfg(unix)]
fn runnable(file: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(file).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn runnable(_file: &Path) -> bool {
    false
}

/// A new name of a scope: serve's pid and a count of this process, so that
/// two serves and two sessions never share one.
pub fn unit_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("podssh-serve-{}-{}.scope", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

/// The arguments of `busctl` that ask the user's manager for the scope
/// `unit` holding `pid`.
pub fn call_args(unit: &str, pid: u32) -> Vec<String> {
    let pid = pid.to_string();
    #[rustfmt::skip]
    let words = [
        "--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
        unit, "fail", "2", "PIDs", "au", "1", pid.as_str(),
        "Description", "s", "podssh serve: one session", "0",
    ];
    words.iter().map(|w| w.to_string()).collect()
}

/// Whether `/proc/PID/cgroup`'s text puts the process in `unit`: cgroup v2
/// has one line, a hybrid host one for each hierarchy.
pub fn in_unit(cgroup: &str, unit: &str) -> bool {
    cgroup.lines().any(|line| line.rsplit('/').next() == Some(unit))
}

#[cfg(target_os = "linux")]
pub(super) use held::{Hold, Moving};

/// The hold of a child between its fork and its exec, Linux's alone.
#[cfg(target_os = "linux")]
mod held {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Instant;

    use super::{call_args, in_unit, Tool, CALL_WAIT, SETTLE};

    /// Two pipes: the child tells its pid on one, and waits on the other
    /// until the move is done or given up. Each end closes at an exec.
    pub(in crate::server) struct Hold {
        tool: Tool,
        unit: String,
        pid: (OwnedFd, OwnedFd),
        go: (OwnedFd, OwnedFd),
    }

    /// The move under way: the child's ends, held until the spawn returns;
    /// serve's ends, held as long, so that the child's write never meets a
    /// closed pipe (its SIGPIPE would end it) and the number of each end
    /// that the child closes stays the same; and the thread that moves it.
    pub(in crate::server) struct Moving {
        child_ends: (OwnedFd, OwnedFd),
        pid_r: Arc<OwnedFd>,
        go_w: Arc<OwnedFd>,
        thread: JoinHandle<Result<String, String>>,
    }

    /// The byte that lets the child go, written when the thread's work ends
    /// by any path, a panic too: the child holds a copy of no writing end,
    /// so nothing else would end its wait.
    struct Go(Arc<OwnedFd>);

    impl Drop for Go {
        fn drop(&mut self) {
            // SAFETY: one byte of static memory, on a descriptor held open.
            unsafe { libc::write(self.0.as_raw_fd(), b"g".as_ptr().cast(), 1) };
        }
    }

    fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 fills two descriptors, each owned once here.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both descriptors are new and owned by nothing else.
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    impl Hold {
        pub(in crate::server) fn new(tool: Tool) -> Result<Hold, String> {
            let fail = |e: std::io::Error| format!("no pipe for the scope's hold: {e}");
            Ok(Hold { tool, unit: super::unit_name(), pid: pipe().map_err(fail)?, go: pipe().map_err(fail)? })
        }

        /// The thread that moves the child, started before the spawn: the
        /// spawn returns only once the child execs. The child is armed
        /// after this, so a thread that did not start holds no child.
        pub(in crate::server) fn start(self) -> Result<Moving, String> {
            let Hold { tool, unit, pid: (pid_r, pid_w), go: (go_r, go_w) } = self;
            let (pid_r, go_w) = (Arc::new(pid_r), Arc::new(go_w));
            let (reader, go) = (pid_r.clone(), Go(go_w.clone()));
            let thread = std::thread::Builder::new()
                .name("podssh-scope".into())
                .spawn(move || {
                    let _go = go;
                    mover(&tool, &unit, &reader)
                })
                .map_err(|e| format!("no thread for the scope: {e}"))?;
            Ok(Moving { child_ends: (pid_w, go_r), pid_r, go_w, thread })
        }
    }

    impl Moving {
        /// The child, between its fork and its exec: its pid to serve, then
        /// a wait for serve's byte, or for the end of the pipe.
        pub(in crate::server) fn arm(&self, cmd: &mut tokio::process::Command) {
            let (tell, wait) = (self.child_ends.0.as_raw_fd(), self.child_ends.1.as_raw_fd());
            let (theirs_r, theirs_w) = (self.pid_r.as_raw_fd(), self.go_w.as_raw_fd());
            // SAFETY: getpid, write, read and close are async-signal-safe,
            // on descriptors that the parent holds open until the spawn
            // returns, and memory of the closure's own.
            unsafe {
                cmd.pre_exec(move || {
                    // serve's ends: no copy of the writing end may keep the
                    // wait below from its end.
                    libc::close(theirs_r);
                    libc::close(theirs_w);
                    let pid = libc::getpid().to_ne_bytes();
                    libc::write(tell, pid.as_ptr().cast(), pid.len());
                    libc::close(tell);
                    let mut byte = 0u8;
                    // A signal's interruption reads again; a byte or the end goes on.
                    loop {
                        let read = libc::read(wait, (&mut byte as *mut u8).cast(), 1);
                        if read != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                            break;
                        }
                    }
                    libc::close(wait);
                    Ok(())
                });
            }
        }

        /// After the spawn: the scope's name, or why the child stays where
        /// it is. The parent's copies of the child's ends close first, so a
        /// spawn that failed before the fork ends the thread's wait.
        pub(in crate::server) fn finish(self) -> Result<String, String> {
            let Moving { child_ends, pid_r, go_w, thread } = self;
            drop(child_ends);
            let moved = thread.join().unwrap_or_else(|_| Err("the scope's thread failed".into()));
            drop((pid_r, go_w));
            moved
        }
    }

    /// Read the child's pid, ask for the scope, and see the child in it; the
    /// caller's [`Go`] then lets the child go.
    fn mover(tool: &Tool, unit: &str, pid_r: &OwnedFd) -> Result<String, String> {
        let pid = read_pid(pid_r)?;
        move_into(tool, unit, pid).map(|()| unit.to_string())
    }

    /// The child's pid, within [`CALL_WAIT`]; the end of the pipe is a
    /// child that never ran.
    fn read_pid(pid_r: &OwnedFd) -> Result<u32, String> {
        let mut poll = libc::pollfd { fd: pid_r.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let wait = CALL_WAIT.as_millis() as libc::c_int;
        // SAFETY: one pollfd of this frame.
        if unsafe { libc::poll(&mut poll, 1, wait) } != 1 {
            return Err("the child did not say its pid in time".into());
        }
        let mut bytes = [0u8; 4];
        // SAFETY: a buffer of this frame of its length.
        let n = unsafe { libc::read(pid_r.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        match (n, i32::from_ne_bytes(bytes)) {
            (4, pid) if pid > 0 => Ok(pid as u32),
            _ => Err("the child ended before it said its pid".into()),
        }
    }

    /// The call, then the child seen in `unit` within [`SETTLE`]: the
    /// manager runs the job after it answers.
    fn move_into(tool: &Tool, unit: &str, pid: u32) -> Result<(), String> {
        let args = call_args(unit, pid);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let busctl = tool.busctl.to_string_lossy();
        let ran =
            pod_core::process::run_bounded(&busctl, &args, None, CALL_WAIT).map_err(|e| format!("{busctl}: {e}"))?;
        if !ran.success() {
            return Err(format!("{busctl}: {}", ran.said()));
        }
        let deadline = Instant::now() + SETTLE;
        let file = format!("/proc/{pid}/cgroup");
        loop {
            if std::fs::read_to_string(&file).is_ok_and(|text| in_unit(&text, unit)) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("asked for {unit}, and the child was not in it within {} s", SETTLE.as_secs()));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
