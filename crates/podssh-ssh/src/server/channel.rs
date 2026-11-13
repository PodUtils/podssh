//! A session channel of `podssh serve` (T-108): what a client asked for on
//! it before its program starts (the environment), and the task that reads
//! the channel from its open to its close.
//!
//! russh gives each message of a channel to the kept `Channel`, and its
//! connection waits while 100 wait unread there: so a task reads each
//! channel at all times, from its open, and hands the bytes to the child's
//! stdin through a queue of its own, never waiting on the child itself. A
//! child that reads nothing holds the connection only once that queue is
//! full ([`INPUT_QUEUE`]); the window of each channel apart is T-118's.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that serve one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use russh::server::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

/// The client's messages that wait for the child's stdin: with russh's
/// packets of 32 KiB, about 4 MiB.
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
}

impl Open {
    /// Split the channel, and start the task that reads it.
    pub(super) fn new(channel: Channel<Msg>, handle: Handle) -> Open {
        let (read, write) = channel.split();
        let (stdin_tx, stdin_rx) = oneshot::channel();
        let (closed_tx, closed) = watch::channel(false);
        tokio::spawn(read_channel(read, stdin_rx, closed_tx));
        Open {
            write: Some(write),
            handle,
            stdin: Some(stdin_tx),
            env: Vec::new(),
            group: Arc::new(AtomicI32::new(0)),
            closed,
            #[cfg(unix)]
            pty: None,
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

/// The task of a channel: its data to the child's stdin once there is one
/// (kept until then, up to [`EARLY_INPUT`]), its EOF as the end of that
/// stdin, and its close as the end of the task.
async fn read_channel(mut read: ChannelReadHalf, mut stdin: oneshot::Receiver<Input>, closed: watch::Sender<bool>) {
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
                if let Ok(pipe) = given {
                    let (tx, rx) = mpsc::channel(INPUT_QUEUE);
                    tokio::spawn(feed(pipe, rx));
                    for bytes in early.drain(..) {
                        let _ = tx.send(bytes).await;
                    }
                    if !eof {
                        queue = Some(tx);
                    }
                }
            }
            message = read.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(tx) = queue.as_ref() {
                        // The feeder drains its queue even after a broken
                        // pipe, so this send never waits on the child alone.
                        let _ = tx.send(data).await;
                    } else if waiting && early_len + data.len() <= EARLY_INPUT {
                        early_len += data.len();
                        early.push(data);
                    }
                }
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
/// stays open for its output). After a write that fails (the child closed
/// its stdin, or ended), the rest is read and dropped, so that the
/// channel's task never waits on it.
async fn feed<B: AsRef<[u8]>>(mut pipe: Input, mut queue: mpsc::Receiver<B>) {
    while let Some(bytes) = queue.recv().await {
        if pipe.write_all(bytes.as_ref()).await.is_err() {
            drop(pipe);
            while queue.recv().await.is_some() {}
            return;
        }
    }
}
