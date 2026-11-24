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

pub mod answer;
pub mod filter;
pub mod probe;
pub mod reach;
pub mod regs;
pub mod run;
pub mod supervisor;
pub mod tracer;

pub use probe::{probe, probe_trace};

use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use pod_term::termios::{flags, Termios, Tty};
use russh::ChannelId;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

use super::channel::{Open, Program};
use super::child::{command, own_session, Running};
use answer::{Answerer, Shared};
use supervisor::Supervisor;
use tracer::Tracer;

use probe::PROBE_WAIT;

/// The bytes that may wait between the client's reader and the discipline.
const PIPE: usize = 64 * 1024;

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
    let (utf8, size, traced) = (grant.utf8, grant.size.subscribe(), grant.traced);
    // TERM is the request's; a socket has no path for SSH_TTY.
    let env = super::env::with_tty(env, &grant.term, None);
    let (mine, theirs) = UnixStream::pair().map_err(|e| format!("no socket for the tty: {e}"))?;
    let (ctl_mine, ctl_theirs) = UnixStream::pair().map_err(|e| format!("no socket for the filter: {e}"))?;
    let _ = ctl_mine.set_read_timeout(Some(PROBE_WAIT));
    let mut cmd = command(shell, &program, env)?;
    // The shell's start files of the marks (T-120), for a login shell.
    if let Some(files) = open.extras.marks.as_ref() {
        files.apply(&mut cmd);
    }
    let stdio = |s: &UnixStream| s.try_clone().map(|c| Stdio::from(OwnedFd::from(c)));
    let fail = |e: std::io::Error| format!("no tty socket for the child: {e}");
    cmd.stdin(stdio(&theirs).map_err(fail)?)
        .stdout(stdio(&theirs).map_err(fail)?)
        .stderr(stdio(&theirs).map_err(fail)?);
    own_session(&mut cmd);
    let ctl = ctl_theirs.as_raw_fd();
    let mut state = Termios::sane();
    if utf8 {
        state.iflag |= flags::IUTF8;
    }
    // The leader is known once the child runs; the tracer sets it sooner.
    let shared = Arc::new(Mutex::new(Shared::new(Tty::new(state).sized(*size.borrow()), 0)));
    let ours = reach::Ours::new(OwnedFd::from(theirs)).map_err(|e| format!("the child's socket: {e}"))?;
    let (told_tx, told) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let answerer = Answerer { ours, shared: shared.clone(), told: told_tx };
    let mut child = if traced {
        // T-777: the child installs the tracer's filter, then waits until
        // this tracer seized it, which a thread of its own must do while
        // the spawn waits for the exec.
        let prog = filter::traced();
        // SAFETY: between the fork and the exec this closure calls prctl,
        // seccomp, getpid, write and read alone, each safe there.
        unsafe {
            cmd.pre_exec(move || {
                filter::install_traced(&prog)?;
                tracer::wait_for_tracer(ctl)
            });
        }
        let (stopping, held) = (stop.clone(), shared.clone());
        let ctl = OwnedFd::from(ctl_mine);
        std::thread::Builder::new()
            .name("podssh-tty-trace".into())
            .spawn(move || {
                let Ok(leader) = tracer::take(&ctl) else { return };
                drop(ctl);
                if let Ok(mut held) = held.lock() {
                    (held.fg, held.sid) = (leader, leader);
                }
                Tracer { leader, answerer, stop: stopping }.run();
            })
            .map_err(|e| format!("no thread for the tty: {e}"))?;
        let spawned = cmd.spawn();
        drop(ctl_theirs);
        spawned.map_err(|e| format!("{}: {}", shell.display(), super::shell::not_started(&e)))?
    } else {
        let prog = filter::program();
        // SAFETY: between the fork and the exec this closure calls prctl,
        // seccomp and sendmsg alone, each safe there, on memory made before.
        unsafe {
            cmd.pre_exec(move || {
                let installed = filter::install(&prog);
                let errno = |e: &std::io::Error| e.raw_os_error().unwrap_or(libc::EINVAL);
                let sent = filter::send_fd(ctl, installed.as_ref().map(|fd| *fd).map_err(errno));
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
        if let Ok(mut held) = shared.lock() {
            (held.fg, held.sid) = (leader, leader);
        }
        let supervisor = Supervisor { listener, answerer, stop: stop.clone() };
        std::thread::Builder::new()
            .name("podssh-tty".into())
            .spawn(move || supervisor.run())
            .map_err(|e| format!("no thread for the tty: {e}"))?;
        child
    };
    let running = Running::take(open, id, &mut child)?;
    // With --share, the seats type through the lease and see the screen
    // (T-861), with the reports of each seat that asked, whose flags are the
    // ones that the child set (T-896).
    let modes = termios_flags(shared.clone());
    let ends = super::share_view::offer_tty(open, tokio::io::duplex(PIPE), modes, &running.write, running.writer());
    let super::share_view::TtyEnds { input, keys, screen, ticks } = ends;
    open.give_stdin(input);
    mine.set_nonblocking(true).map_err(|e| format!("the tty socket: {e}"))?;
    let mine = tokio::net::UnixStream::from_std(mine).map_err(|e| format!("the tty socket: {e}"))?;
    let (from_child, to_child) = mine.into_split();
    let (exited_tx, exited) = watch::channel(false);
    let mut ends = run::Ends { keys, from_child, to_child, screen, ticks };
    // The message of the day comes before the child's first byte (T-119).
    let motd = open.extras.motd.take();
    let task = tokio::spawn(async move {
        if let Some(motd) = motd
            && ends.screen.write_all(&motd).await.is_err()
        {
            return;
        }
        run::run(shared, told, ends, size, exited, stop).await;
    });
    // The files of the marks go when the session does.
    let (marks, closed) = (open.extras.marks.take(), open.closed.clone());
    tokio::spawn(async move {
        running.finish(child, vec![task], exited_tx, closed).await;
        drop(marks);
    });
    Ok(())
}

/// The ECHO and ICANON flags that the child set, which local echo's
/// reports of a shared shell carry (T-896): the termios state that serve
/// answers the child's calls from, read at each report.
fn termios_flags(shared: Arc<Mutex<Shared>>) -> super::share_told::FlagsOf {
    Box::new(move || {
        let lflag = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).tty.state().lflag;
        crate::predict::report::Flags { echo: lflag & flags::ECHO != 0, canonical: lflag & flags::ICANON != 0 }
    })
}
