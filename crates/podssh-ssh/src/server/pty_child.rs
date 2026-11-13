//! A program of `podssh serve` on a pty (T-110): the pty granted to a
//! channel, its size from the request and each `window-change`, and the
//! child with the slave as its standard files and its controlling terminal.
//!
//! The master's output goes to the channel as data: on a pty, stdout and
//! stderr are one stream, as under sshd. The client's data goes to the
//! master. A read of the master that fails with EIO is the end of the
//! output (each slave is closed), not an error.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use russh::{ChannelId, Pty};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use super::channel::{Open, Program};
use super::child::{command, pump, Running};
use super::pty::{self, Pair};
use crate::terminal::Size;

/// A pty granted to a channel, until its program starts; then its master
/// stays here for `window-change`.
pub(super) struct Granted {
    master: Arc<AsyncFd<OwnedFd>>,
    /// The slave, held until the child has its copies.
    slave: Option<OwnedFd>,
    name: String,
    term: String,
}

impl Granted {
    /// Take the probe's `pair` for a request of `term`, `size` and `modes`.
    /// `Err` is why the pty cannot serve, and the request is refused.
    pub(super) fn new(pair: Pair, term: &str, size: Size, modes: &[(Pty, u32)]) -> Result<Granted, String> {
        let Pair { master, slave, name } = pair;
        // A mode that the kernel refuses is passed over, as sshd does.
        pty::set_modes(slave.as_raw_fd(), modes).map_err(|e| format!("{name}: its modes: {e}"))?;
        pty::set_size(master.as_raw_fd(), size).map_err(|e| format!("{name}: its size: {e}"))?;
        nonblocking(&master).map_err(|e| format!("{name}: {e}"))?;
        // SAFETY: the AsyncFd owns the master, which stays open and the same
        // until the AsyncFd drops it.
        let master = unsafe { AsyncFd::register(master) }.map_err(|e| format!("{name}: {}", e.into_parts().1))?;
        Ok(Granted { master: Arc::new(master), slave: Some(slave), name, term: pty::term_of(term) })
    }

    /// A new size (`window-change`); the kernel tells the child's
    /// foreground group with SIGWINCH.
    pub(super) fn resize(&self, size: Size) {
        let _ = pty::set_size(self.master.get_ref().as_raw_fd(), size);
    }
}

fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor held open; only the flags change.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags == -1 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Start `program` on the pty of `open`, and the task that serves it to its
/// end. `TERM` is the request's and `SSH_TTY` names the slave, as sshd sets
/// them.
pub(super) fn spawn(
    open: &mut Open,
    id: ChannelId,
    shell: &Path,
    program: Program<'_>,
    env: Vec<(OsString, OsString)>,
) -> Result<(), String> {
    let Some(granted) = open.pty.as_mut() else { return Err("no pty on this channel".into()) };
    let Some(slave) = granted.slave.take() else { return Err("a program ran on this pty already".into()) };
    let env = super::env::with_tty(env, &granted.term, &granted.name);
    let mut cmd = command(shell, &program, env)?;
    let copy = |what: &str| slave.try_clone().map_err(|e| format!("{}: {what}: {e}", granted.name));
    cmd.stdin(Stdio::from(copy("stdin")?)).stdout(Stdio::from(copy("stdout")?)).stderr(Stdio::from(copy("stderr")?));
    // A session of its own whose controlling terminal is the slave: Ctrl-C
    // on the pty reaches the child's foreground group, and a hangup its
    // session. std puts the standard files in place before this runs.
    // SAFETY: setsid and ioctl are async-signal-safe and touch no memory of
    // the parent.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    // Each copy of the slave in this process closes now, or the master
    // never sees the end of the child's output.
    drop(cmd);
    drop(slave);
    let mut child = spawned.map_err(|e| format!("{}: {}", shell.display(), super::shell::not_started(&e)))?;
    let running = Running::take(open, id, &mut child)?;
    let Some(granted) = open.pty.as_ref() else { return Err("no pty on this channel".into()) };
    let master = granted.master.clone();
    open.give_stdin(Box::new(Master(master.clone())));
    let (exited_tx, exited) = watch::channel(false);
    let output = tokio::spawn(pump(Master(master), running.write.make_writer(), exited));
    tokio::spawn(running.finish(child, vec![output], exited_tx, open.closed.clone()));
    Ok(())
}

/// The master, read and written without blocking.
struct Master(Arc<AsyncFd<OwnedFd>>);

impl AsyncRead for Master {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            let read = guard.try_io(|fd| {
                // SAFETY: the buffer is valid for its length, and the
                // descriptor is held open by the AsyncFd.
                let n = unsafe { libc::read(fd.get_ref().as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match read {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // Each slave is closed: the end of the output.
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Poll::Ready(Ok(())),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Master {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            let written = guard.try_io(|fd| {
                // SAFETY: the bytes are valid for their length, and the
                // descriptor is held open by the AsyncFd.
                let n = unsafe { libc::write(fd.get_ref().as_raw_fd(), data.as_ptr().cast(), data.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match written {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A pty has no half-close: the client's EOF ends its writing alone,
    /// and the output goes on, as under sshd.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
