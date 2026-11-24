//! The channels of a shared shell (T-837): the owner's output copied to
//! each watcher, and the one gate of a name's right. A shell on serve's own
//! tty (T-861) is shared the same way: the discipline's input takes the
//! writers' bytes through the lease, and its screen goes to each seat.
//!
//! The gate is the attach: a channel logged in under a name that only
//! watches gets a sink for its input, so no byte of it (typed, pasted
//! before the shell request, or sent as extended data) has a path to the
//! pty. No write site checks a right: a channel that may not write holds
//! nothing to write to.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that share one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, watch};

use super::channel::{Input, Open};
use super::share::{Hub, Mode, Pass, Seat, Shares};
use crate::terminal::Size;

/// Why a name's channel runs nothing: it attaches, and that is all.
pub(super) const RUNS_NOTHING: &str =
    "this login is a shared shell's name: it attaches to that shell with a shell request, and runs nothing else";

/// Why a name's shell request finds no shell.
const ENDED: &str = "the shared shell ended";

/// The owner's line where the names could not be drawn.
const NO_RANDOM: &str = "podssh serve: this shell is not shared: the system gave no random bytes for its names\r\n";

/// The screen of a shell on serve's own tty: the owner's channel, or a tee
/// of it to each seat.
pub(super) type Screen = Box<dyn AsyncWrite + Send + Unpin>;

/// Open a shared shell with the owner's seat: `pty` takes the writers'
/// bytes under the lease and `resize` sets the least size. Its names go
/// to the owner's line, told once when the shell starts.
pub(super) fn open_hub(
    open: &mut Open,
    shares: &Shares,
    pty: Input,
    resize: Box<dyn Fn(Size) + Send + Sync>,
    size: Size,
) -> Arc<Seat> {
    let owner = Hub::open(shares, pty, resize, size);
    open.told = Some(shares.mint(&owner.hub).map_or_else(|| NO_RANDOM.to_string(), |names| names.told()));
    open.seat = Some(owner.clone());
    owner
}

/// With `--share`, the login shell on serve's own tty (`--pty line` or
/// `notify`, T-861): `keys`, the discipline's input, takes each writer's
/// bytes through the lease, and `screen`, the discipline's output, goes to
/// each seat too, its echo among it. The owner's input and screen; without
/// an offer, `keys` and `screen` as they came.
#[cfg(unix)]
pub(super) fn offer_tty<W>(open: &mut Open, keys: Input, screen: W) -> (Input, Screen)
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let Some(shares) = open.offer.take() else { return (keys, Box::new(screen)) };
    let Some(sizes) = open.line.as_ref().map(|grant| grant.size.clone()) else { return (keys, Box::new(screen)) };
    let now = *sizes.borrow();
    let size = Size { cols: now.cols.into(), rows: now.rows.into(), px_width: 0, px_height: 0 };
    // The least size of the seats goes to the discipline, as a window
    // change of the owner's does without --share.
    let resize = move |least: Size| {
        let next = super::line::size_of(least.cols, least.rows);
        sizes.send_if_modified(|now| std::mem::replace(now, next) != next);
    };
    let owner = open_hub(open, &shares, keys, Box::new(resize), size);
    (owner.writer(), Box::new(Tee::new(screen, owner.hub.clone())))
}

/// Attach the channel `open` to the shell of `pass`: its output from now
/// on to the channel, and the channel's input to the pty only where the
/// name may write. This is the one place where a right is applied.
pub(super) fn attach(open: &mut Open, pass: &Pass) -> Result<(), String> {
    if open.started() {
        return Err("a program runs on this channel already".into());
    }
    let Some(from) = pass.hub.subscribe() else { return Err(ENDED.into()) };
    let Some(write) = open.write.take() else { return Err(ENDED.into()) };
    let seat = pass.hub.seat(open.asked.take());
    let input: Input = match pass.mode {
        Mode::Write => seat.writer(),
        // A watcher's bytes go nowhere: its channel never holds the pty.
        Mode::Read => Box::new(tokio::io::sink()),
    };
    open.give_input(input);
    open.seat = Some(seat.clone());
    tokio::spawn(view(from, write, open.closed.clone(), seat));
    Ok(())
}

/// A name's `pty-req`: no pty of its own, only its size for the shell's.
pub(super) fn ask_pty(open: Option<&mut Open>, cols: u32, rows: u32, px_width: u32, px_height: u32) -> bool {
    let Some(open) = open.filter(|open| !open.started() && open.asked.is_none()) else { return false };
    #[cfg(unix)]
    let size = super::pty::size_of(cols, rows, px_width, px_height);
    #[cfg(not(unix))]
    let size = crate::terminal::Size { cols, rows, px_width, px_height };
    open.asked = Some(size);
    true
}

/// The owner's line after its shell started, once: the names, or why the
/// shell is not shared although `--share` asked. An offer that no tty took
/// (a shell on pipes, with no screen to share) goes unsaid.
pub(super) fn told(open: &mut Open) -> Option<String> {
    open.offer = None;
    open.told.take()
}

/// The owner's output: to the owner's channel, then a copy to each
/// watcher. Its end, the end of the shell's output, ends the names.
pub(super) struct Tee<W> {
    to: W,
    hub: Arc<Hub>,
}

impl<W> Tee<W> {
    pub(super) fn new(to: W, hub: Arc<Hub>) -> Tee<W> {
        Tee { to, hub }
    }
}

impl<W> Drop for Tee<W> {
    fn drop(&mut self) {
        self.hub.end();
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Tee<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let n = ready!(Pin::new(&mut this.to).poll_write(cx, buf))?;
        this.hub.said(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.to).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.to).poll_shutdown(cx)
    }
}

/// A seat's view: the shell's output to its channel until the shell ends,
/// then a status of 0, EOF and close; a channel that closes first ends it.
/// A seat that falls behind skips to the present.
async fn view(
    mut from: broadcast::Receiver<Bytes>,
    write: ChannelWriteHalf<Msg>,
    mut closed: watch::Receiver<bool>,
    seat: Arc<Seat>,
) {
    let mut to = write.make_writer();
    loop {
        let next = tokio::select! {
            next = from.recv() => next,
            () = gone(&mut closed) => return,
        };
        match next {
            Ok(bytes) => {
                if to.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    drop(seat);
    let _ = write.exit_status(0).await;
    let _ = write.eof().await;
    let _ = write.close().await;
}

/// Wait until the channel closed. The guard of `wait_for` is dropped in
/// its statement, so the task stays Send.
async fn gone(closed: &mut watch::Receiver<bool>) {
    let _ = closed.wait_for(|closed| *closed).await;
}
