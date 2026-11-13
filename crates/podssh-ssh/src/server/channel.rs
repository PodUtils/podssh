//! A session channel of `podssh serve` (T-108): what a client asked for on
//! it before its program starts (the environment), and the task that reads
//! the channel from its open to its close.
//!
//! russh gives each message of a channel to the kept `Channel`, and its
//! connection waits while 100 wait unread there: so a task reads each
//! channel at all times, from its open, and hands the bytes to the child's
//! stdin through a queue of its own, never waiting on the child itself.
//!
//! The channel's window opens as the child takes the bytes, not as they
//! arrive (T-118, podssh's patch of russh, `Handler::window_on_read`): the
//! feeder grants each chunk back once it is written, or once it is dropped
//! (a child that closed its stdin). So a client sends at most one window
//! ahead of the child, a child that reads nothing holds its own channel
//! alone, and the bytes that wait in serve for one channel are at most its
//! window.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that serve one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use russh::server::{Handle, Msg};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

/// The client's messages that wait for the child's stdin: with russh's
/// packets of 32 KiB, about 4 MiB; a client that keeps to its window fills
/// an eighth of it at most (T-118).
pub const INPUT_QUEUE: usize = 128;

/// What the client may send before its program starts, kept for it.
pub const EARLY_INPUT: usize = 1 << 20;

/// Where the client's data goes: the child's stdin, a pty's master, or the
/// SFTP server's input (T-112).
pub(super) type Input = Box<dyn AsyncWrite + Send + Unpin>;

/// What a channel asks to run: a command (`exec`), or the login shell
/// (`shell`).
pub(super) enum Program<'a> {
    Command(&'a [u8]),
    Login,
}

/// One open session channel.
pub(super) struct Open {
    /// Its writing half, until a program takes it.
    pub(super) write: Option<ChannelWriteHalf<Msg>>,
    /// The connection's handle, for `exit-signal`, which the channel's half
    /// does not send. Both go through one queue, so their order holds.
    pub(super) handle: Handle,
    /// Where the child's input goes to the reading task.
    stdin: Option<oneshot::Sender<Input>>,
    /// The `env` requests taken, in order.
    pub(super) env: Vec<(String, String)>,
    /// The child's process group, 0 while none runs.
    pub(super) group: Arc<AtomicI32>,
    /// True once the client closed the channel, or the connection ended.
    pub(super) closed: watch::Receiver<bool>,
    /// The pty granted by a `pty-req` (T-110), from then to the close.
    #[cfg(unix)]
    pub(super) pty: Option<super::pty_child::Granted>,
    /// A pty request granted with serve as the line discipline (T-111).
    #[cfg(unix)]
    pub(super) line: Option<super::line::LineGrant>,
}

impl Open {
    /// Split the channel, and start the task that reads it. `group` is the
    /// slot of the server's stop for this channel's child (T-117).
    pub(super) fn new(channel: Channel<Msg>, handle: Handle, group: Arc<AtomicI32>) -> Open {
        let window = Window { handle: handle.clone(), id: channel.id() };
        let (read, write) = channel.split();
        let (stdin_tx, stdin_rx) = oneshot::channel();
        let (closed_tx, closed) = watch::channel(false);
        tokio::spawn(read_channel(read, stdin_rx, closed_tx, window));
        Open {
            write: Some(write),
            handle,
            stdin: Some(stdin_tx),
            env: Vec::new(),
            group,
            closed,
            #[cfg(unix)]
            pty: None,
            #[cfg(unix)]
            line: None,
        }
    }

    /// Whether a program runs, or ran, on this channel: a channel runs one.
    pub(super) fn started(&self) -> bool {
        self.write.is_none()
    }

    /// Give the child's input to the reading task, with what came early.
    pub(super) fn give_stdin(&mut self, input: Input) {
        if let Some(to) = self.stdin.take() {
            let _ = to.send(input);
        }
    }

    /// Give the reading task where the channel's data goes, as for a child.
    pub(super) fn give_input(&mut self, input: Input) {
        self.give_stdin(input);
    }

    /// A `signal` request (RFC 4254, section 6.9): to the child's whole
    /// process group, as the child leads one of its own. A name that podssh
    /// does not know is passed over, as the request has no reply.
    pub(super) fn signal(&self, signal: &russh::Sig) {
        let group = self.group.load(Ordering::SeqCst);
        let Some(number) = crate::signals::number(signal) else { return };
        #[cfg(unix)]
        if group > 0 {
            // SAFETY: kill has no memory effect; a group that ended gives ESRCH.
            unsafe {
                libc::kill(-group, number);
            }
        }
        #[cfg(not(unix))]
        let _ = (group, number);
    }
}

/// A channel's window, opened by the bytes that its reader took (T-118).
#[derive(Clone)]
pub(super) struct Window {
    pub(super) handle: Handle,
    pub(super) id: ChannelId,
}

impl Window {
    /// Give `bytes` back to the client's window. A session that ended
    /// takes nothing, and needs nothing.
    pub(super) fn grant(&self, bytes: usize) {
        if bytes > 0 {
            let _ = self.handle.grant_window(self.id, u32::try_from(bytes).unwrap_or(u32::MAX));
        }
    }
}

/// The task of a channel: its data to the child's stdin once there is one
/// (kept until then, up to [`EARLY_INPUT`]), its EOF as the end of that
/// stdin, and its close as the end of the task. Each byte that no one will
/// read (extended data, data with no program, past what is kept early) is
/// given back to the window at once, so that the client never waits on it.
async fn read_channel(
    mut read: ChannelReadHalf,
    mut stdin: oneshot::Receiver<Input>,
    closed: watch::Sender<bool>,
    window: Window,
) {
    // The bytes of russh's messages, kept as they came.
    let mut early = Vec::new();
    let mut early_len = 0usize;
    let mut eof = false;
    let mut waiting = true;
    let mut queue: Option<mpsc::Sender<_>> = None;
    loop {
        tokio::select! {
            given = &mut stdin, if waiting => {
                waiting = false;
                // Err: the channel closed before a program started.
                match given {
                    Ok(pipe) => {
                        let (tx, rx) = mpsc::channel(INPUT_QUEUE);
                        tokio::spawn(feed(pipe, rx, window.clone()));
                        for bytes in early.drain(..) {
                            let _ = tx.send(bytes).await;
                        }
                        if !eof {
                            queue = Some(tx);
                        }
                    }
                    // The channel closed before a program started.
                    Err(_) => {
                        window.grant(early_len);
                        early.clear();
                    }
                }
            }
            message = read.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(tx) = queue.as_ref() {
                        // The feeder drains its queue even after a broken
                        // pipe, and grants each chunk back, so this send
                        // never waits on the child alone.
                        if let Err(lost) = tx.send(data).await {
                            window.grant(lost.0.len());
                        }
                    } else if waiting && early_len + data.len() <= EARLY_INPUT {
                        early_len += data.len();
                        early.push(data);
                    } else {
                        window.grant(data.len());
                    }
                }
                // No child reads a stream of extended data.
                Some(ChannelMsg::ExtendedData { data, .. }) => window.grant(data.len()),
                // The end of the child's stdin, once the queue is written.
                Some(ChannelMsg::Eof) => {
                    eof = true;
                    queue = None;
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    }
    let _ = closed.send(true);
}

/// Write the queue to the child's input, then close it (a pty's master
/// stays open for its output), granting each chunk back to the window once
/// it is written: the client sends no more than the child takes. After a
/// write that fails (the child closed its stdin, or ended), the rest is
/// read, dropped and granted, so that neither the channel's task nor the
/// client waits on it, as sshd discards what a closed stdin no longer takes.
async fn feed<B: AsRef<[u8]>>(mut pipe: Input, mut queue: mpsc::Receiver<B>, window: Window) {
    while let Some(bytes) = queue.recv().await {
        let bytes = bytes.as_ref();
        let written = pipe.write_all(bytes).await;
        window.grant(bytes.len());
        if written.is_err() {
            drop(pipe);
            while let Some(bytes) = queue.recv().await {
                window.grant(bytes.as_ref().len());
            }
            return;
        }
    }
}
