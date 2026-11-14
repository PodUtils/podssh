//! The probes of the two routes (T-776, T-777), each made once for the
//! process: whether serve can answer a child's tty calls here by user
//! notification, and else by `ptrace`. Each asks `TIOCGWINSZ` of a socket
//! of its own, which the child's `test -t 0` does not ask, so a defect of
//! `TCGETS` shows in a session and not as a host that refuses.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pod_term::termios::{Termios, Tty};
use pod_term::window::Size;
use tokio::sync::mpsc;

use super::answer::{Answerer, Shared};
use super::supervisor::Supervisor;
use super::tracer::{self, Tracer};
use super::{filter, reach};

/// How long a probe waits for its own call to come back.
pub const PROBE_WAIT: Duration = Duration::from_secs(2);

/// The size that each probe's answer carries.
const SIZE: Size = Size { rows: 24, cols: 80 };

static NOTIFIED: OnceLock<Result<(), String>> = OnceLock::new();
static TRACED: OnceLock<Result<(), String>> = OnceLock::new();

/// Whether serve can answer a child's tty calls here by user notification.
pub fn probe() -> Result<(), String> {
    NOTIFIED.get_or_init(by_notification).clone()
}

/// Whether serve can answer them by `ptrace`, where notification is
/// refused (T-777).
pub fn probe_trace() -> Result<(), String> {
    TRACED.get_or_init(by_trace).clone()
}

/// What answers the probe's call: a socket's copy, and a state of 24x80.
fn answerer(asker_end: &UnixStream) -> Result<Answerer, String> {
    let copy = asker_end.try_clone().map_err(|e| e.to_string())?;
    let ours = reach::Ours::new(OwnedFd::from(copy)).map_err(|e| e.to_string())?;
    let shared = Arc::new(Mutex::new(Shared::new(Tty::new(Termios::sane()).sized(SIZE), 0)));
    let (told, _) = mpsc::unbounded_channel();
    Ok(Answerer { ours, shared, told })
}

/// The 8 bytes of the answer that the asker must read.
fn want() -> Vec<u8> {
    [SIZE.rows.to_ne_bytes(), SIZE.cols.to_ne_bytes(), [0, 0], [0, 0]].concat()
}

/// The probe: a thread installs the filter (which binds that thread alone,
/// and ends with it) and asks `TIOCGWINSZ` of a socket; this thread answers
/// it through the listener, and the asker reads the answer. The request is
/// one that the child's `test -t 0` does not make, so a defect of `TCGETS`
/// shows in the session, not as a host that refuses.
fn by_notification() -> Result<(), String> {
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
    let answerer = answerer(&asker_end)?;
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor = Supervisor { listener, answerer, stop: stop.clone() };
    let answering = std::thread::spawn(move || supervisor.run());
    let asked = asked_rx.recv_timeout(PROBE_WAIT);
    // The supervisor ends, and its listener with it.
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = answering.join();
    match asked {
        Ok((0, answer)) if answer[..] == want()[..] => Ok(()),
        Ok((0, _)) => Err("the answer to TIOCGWINSZ did not reach the asker's memory".into()),
        Ok((_, _)) => Err("serve's answer to a tty call did not come back".into()),
        Err(_) => Err(format!("no answer to a tty call within {} s", PROBE_WAIT.as_secs())),
    }
}

/// The probe of `ptrace`: a child forked here installs the tracer's filter
/// and waits to be seized; this thread seizes it, answers its `TIOCGWINSZ`
/// at the call's stop, and reads its exit: 0 where the answer came.
fn by_trace() -> Result<(), String> {
    let (asker_end, _other) = UnixStream::pair().map_err(|e| format!("no socket pair: {e}"))?;
    let (ctl_mine, ctl_theirs) = UnixStream::pair().map_err(|e| format!("no socket pair: {e}"))?;
    let _ = ctl_mine.set_read_timeout(Some(PROBE_WAIT));
    let answerer = answerer(&asker_end)?;
    let (fd, ctl, program, want) = (asker_end.as_raw_fd(), ctl_theirs.as_raw_fd(), filter::traced(), want());
    // SAFETY: the child calls prctl, seccomp, write, read, ioctl and _exit
    // alone, each safe after a fork, on memory made before it.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            if filter::install_traced(&program).is_err() || tracer::wait_for_tracer(ctl).is_err() {
                libc::_exit(2);
            }
            let mut answer = [0u8; 8];
            let rc = libc::ioctl(fd, 0x5413 as _, answer.as_mut_ptr());
            libc::_exit(if rc == 0 && answer[..] == want[..] { 0 } else { 1 });
        }
    }
    if pid < 0 {
        return Err(format!("no child for the probe: {}", std::io::Error::last_os_error()));
    }
    drop(ctl_theirs);
    let ctl = OwnedFd::from(ctl_mine);
    let seized = tracer::take(&ctl);
    // The bound is a kill of the child while it is traced: `done` is set,
    // under its lock, before the reap, so the kill never meets a pid that
    // was given again.
    let done = Arc::new(Mutex::new(false));
    let seen = done.clone();
    std::thread::spawn(move || {
        std::thread::sleep(PROBE_WAIT * 2);
        let done = seen.lock().unwrap_or_else(|p| p.into_inner());
        if !*done {
            // SAFETY: a signal to the probe's child, not reaped yet.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    });
    if seized.is_ok() {
        Tracer { leader: pid, answerer, stop: Arc::new(AtomicBool::new(true)) }.run();
    }
    drop(ctl);
    if seized.is_err() {
        // SAFETY: a signal to this thread's child, not reaped yet.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    *done.lock().unwrap_or_else(|p| p.into_inner()) = true;
    let mut status = 0;
    // SAFETY: waitpid writes one status of this thread's own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    match (seized, libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status))) {
        (Err(e), _) => Err(format!("ptrace is refused: {e}")),
        (Ok(_), Some(0)) => Ok(()),
        (Ok(_), Some(2)) => Err("the tracer's filter is refused".into()),
        (Ok(_), _) => Err("the answer to a traced call did not come back".into()),
    }
}
