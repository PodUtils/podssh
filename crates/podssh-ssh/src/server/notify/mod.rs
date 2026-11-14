//! A tty for the child where no pty opens, answered by serve (T-776, route
//! 2a of T-248's study): the child's descriptors 0 to 2 are one `AF_UNIX`
//! stream socket, and a seccomp filter of its own, installed between its
//! fork and its exec, sends its tty `ioctl`s and its opens to serve as user
//! notifications. serve answers them from one termios state
//! ([`supervisor`]), which also drives pod-term's termios mode between the
//! client and the socket ([`run`]): the child sees a tty (`test -t 0`,
//! `stty`, job control, a full-screen program) with no `/dev/ptmx` and no
//! namespace. No code of serve's goes into the child, and serve answers
//! only for the socket that it gave.
//!
//! [`probe`] says whether the host allows it, once for the process: a
//! thread of serve's own installs the filter, asks `TCGETS` of a socket
//! of its own, and the answer must come back through the listener. Where it
//! does not, a `pty-req` falls to the line discipline of T-111.

pub mod filter;
pub mod reach;
pub mod run;
pub mod supervisor;

use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pod_term::termios::{flags, Termios, Tty};
use russh::ChannelId;
use tokio::sync::{mpsc, watch};

use super::channel::{Open, Program};
use super::child::{command, own_session, Running};
use supervisor::{Shared, Supervisor};

/// How long the probe waits for its own call to come back.
const PROBE_WAIT: Duration = Duration::from_secs(2);

/// The bytes that may wait between the client's reader and the discipline.
const PIPE: usize = 64 * 1024;

static PROBED: OnceLock<Result<(), String>> = OnceLock::new();

/// Whether serve can answer a child's tty calls here: the probe's result,
/// made once for the process.
pub fn probe() -> Result<(), String> {
    PROBED.get_or_init(probe_now).clone()
}

/// The probe: a thread installs the filter (which binds that thread alone,
/// and ends with it) and asks `TIOCGWINSZ` of a socket; this thread answers
/// it through the listener, and the asker reads the answer. The request is
/// one that the child's `test -t 0` does not make, so a defect of `TCGETS`
/// shows in the session, not as a host that refuses.
fn probe_now() -> Result<(), String> {
    let (asker_end, _other) = UnixStream::pair().map_err(|e| format!("no socket pair: {e}"))?;
    let (lfd_tx, lfd_rx) = std::sync::mpsc::channel::<Result<OwnedFd, String>>();
    let (asked_tx, asked_rx) = std::sync::mpsc::channel::<(i32, [u8; 8])>();
    let fd = asker_end.as_raw_fd();
    let program = filter::program();
    std::thread::Builder::new()
        .name("podssh-tty-probe".into())
        .spawn(move || {
            // SAFETY: the program lives for the call.
            let listener = match unsafe { filter::install(&program) } {
                Ok(lfd) => lfd,
                Err(e) => {
                    let _ = lfd_tx.send(Err(format!("seccomp's user notification is refused: {e}")));
                    return;
                }
            };
            // SAFETY: a new descriptor of this thread's own.
            let owned = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(listener) };
            if lfd_tx.send(Ok(owned)).is_err() {
                return;
            }
            let mut answer = [0u8; 8];
            // SAFETY: TIOCGWINSZ writes 8 bytes, which `answer` holds. A
            // listener that closes unanswered ends the call with ENOSYS.
            let rc = unsafe { libc::ioctl(fd, 0x5413 as _, answer.as_mut_ptr()) };
            let _ = asked_tx.send((rc, answer));
        })
        .map_err(|e| format!("no thread for the probe: {e}"))?;
    let listener = lfd_rx.recv_timeout(PROBE_WAIT).map_err(|_| "the probe's thread said nothing".to_string())??;
    let copy = asker_end.try_clone().map_err(|e| e.to_string())?;
    let ours = reach::Ours::new(OwnedFd::from(copy)).map_err(|e| e.to_string())?;
    let size = pod_term::window::Size { rows: 24, cols: 80 };
    let shared = Arc::new(Mutex::new(Shared::new(Tty::new(Termios::sane()).sized(size), 0)));
    let (told, _) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor = Supervisor { listener, ours, shared, told, stop: stop.clone() };
    let answering = std::thread::spawn(move || supervisor.run());
    let asked = asked_rx.recv_timeout(PROBE_WAIT);
    // The supervisor ends, and its listener with it.
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = answering.join();
    let want = [24u16.to_ne_bytes(), 80u16.to_ne_bytes()].concat();
    match asked {
        Ok((0, answer)) if answer[..4] == want[..] => Ok(()),
        Ok((0, _)) => Err("the answer to TIOCGWINSZ did not reach the asker's memory".into()),
        Ok((_, _)) => Err("serve's answer to a tty call did not come back".into()),
        Err(_) => Err(format!("no answer to a tty call within {} s", PROBE_WAIT.as_secs())),
    }
}

/// Start `program` on a socket whose tty calls serve answers, and the
/// tasks that serve it to its end. `Err` is the line for the client's stderr.
pub(super) fn spawn(
    open: &mut Open,
    id: ChannelId,
    shell: &Path,
    program: Program<'_>,
    env: Vec<(OsString, OsString)>,
) -> Result<(), String> {
    let Some(grant) = open.line.as_ref() else { return Err("no pty on this channel".into()) };
    let (utf8, size) = (grant.utf8, grant.size.subscribe());
    // TERM is the request's; a socket has no path for SSH_TTY.
    let env = super::env::with_tty(env, &grant.term, None);
    let (mine, theirs) = UnixStream::pair().map_err(|e| format!("no socket for the tty: {e}"))?;
    let (ctl_mine, ctl_theirs) = UnixStream::pair().map_err(|e| format!("no socket for the filter: {e}"))?;
    let _ = ctl_mine.set_read_timeout(Some(PROBE_WAIT));
    let mut cmd = command(shell, &program, env)?;
    let stdio = |s: &UnixStream| s.try_clone().map(|c| Stdio::from(OwnedFd::from(c)));
    let fail = |e: std::io::Error| format!("no tty socket for the child: {e}");
    cmd.stdin(stdio(&theirs).map_err(fail)?)
        .stdout(stdio(&theirs).map_err(fail)?)
        .stderr(stdio(&theirs).map_err(fail)?);
    own_session(&mut cmd);
    let prog = filter::program();
    let ctl = ctl_theirs.as_raw_fd();
    // SAFETY: between the fork and the exec this closure calls prctl,
    // seccomp and sendmsg alone, each safe there, on memory made before.
    unsafe {
        cmd.pre_exec(move || {
            let installed = filter::install(&prog);
            let sent = filter::send_fd(
                ctl,
                installed.as_ref().map(|fd| *fd).map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL)),
            );
            match installed {
                Ok(fd) => {
                    libc::close(fd);
                    if sent {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                }
                Err(e) => Err(e),
            }
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("{}: {}", shell.display(), super::shell::not_started(&e)))?;
    drop(ctl_theirs);
    let listener = match filter::recv_fd(&OwnedFd::from(ctl_mine)) {
        Ok(listener) => listener,
        Err(e) => {
            let _ = child.start_kill();
            return Err(format!("no listener of the child's filter: {e}"));
        }
    };
    let leader = child.id().map_or(0, |pid| pid as i32);
    let mut state = Termios::sane();
    if utf8 {
        state.iflag |= flags::IUTF8;
    }
    let shared = Arc::new(Mutex::new(Shared::new(Tty::new(state).sized(*size.borrow()), leader)));
    let ours = reach::Ours::new(OwnedFd::from(theirs)).map_err(|e| format!("the child's socket: {e}"))?;
    let (told_tx, told) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor = Supervisor { listener, ours, shared: shared.clone(), told: told_tx, stop: stop.clone() };
    std::thread::Builder::new()
        .name("podssh-tty".into())
        .spawn(move || supervisor.run())
        .map_err(|e| format!("no thread for the tty: {e}"))?;
    let running = Running::take(open, id, &mut child)?;
    let (keys_in, keys) = tokio::io::duplex(PIPE);
    open.give_stdin(Box::new(keys_in));
    mine.set_nonblocking(true).map_err(|e| format!("the tty socket: {e}"))?;
    let mine = tokio::net::UnixStream::from_std(mine).map_err(|e| format!("the tty socket: {e}"))?;
    let (from_child, to_child) = mine.into_split();
    let (exited_tx, exited) = watch::channel(false);
    let ends = run::Ends { keys, from_child, to_child, screen: running.write.make_writer() };
    let task = tokio::spawn(run::run(shared, told, ends, size, exited, stop));
    tokio::spawn(running.finish(child, vec![task], exited_tx, open.closed.clone()));
    Ok(())
}
