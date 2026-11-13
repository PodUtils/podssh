//! A link of the road: a byte stream for the resumable layer, whose two ways
//! are numbered pieces through the [`Carrier`]. A client draws the link's id
//! and knocks at the node's door with it ([`dial`]); the node takes the
//! hello ([`accept`]); then each end sends its way and reads the other's.
//!
//! What the layer writes at once goes together. When it fits a note
//! ([`Carrier::room`]), it goes at once, in its note on the board: the
//! handshakes and the small frames move at the board's speed. A larger
//! write waits for its host's pace, and the bytes that the layer writes in
//! the meantime join it, up to [`PIECE_MOST`]: the fewer the uploads, the
//! less the road asks of a host. The small writes that queue behind a
//! piece go together in the next write, in order. An empty write ends a
//! way. A write that is not sent ends the link; the layer sends again what
//! the far end did not acknowledge, on the next link, as over the Piping
//! Server road.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::carrier::Carrier;
use super::keys::{LinkId, Way};
use super::PIECE_MOST;
use crate::session::OsEntropy;

/// Each direction of the pipe between the layer and a link: a whole piece.
pub const PIPE: usize = PIECE_MOST;
/// How long a write gathers the layer's bytes after each read: what the
/// layer writes at once goes in one note or one piece.
pub const GATHER: Duration = Duration::from_millis(200);
/// How long a reader waits for the far end's next piece: the layer's
/// heartbeat sends one at its pace, so this long with none is a far end
/// that is gone.
pub const PIECE_WAIT: Duration = Duration::from_secs(10 * 60);
/// How long a node's door waits for a hello, and a client for its link.
pub const DOOR_WAIT: Duration = Duration::from_secs(5 * 60);

/// A link: the layer's end of a pipe whose far end a task carries over the
/// road. Dropping it ends the task.
pub struct Link {
    io: DuplexStream,
    task: AbortHandle,
    pub id: LinkId,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AsyncRead for Link {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// A client's link: a new id, its hello at the node's door, taken by the
/// node within [`DOOR_WAIT`], then the up way sent and the down way read.
pub async fn dial(carrier: Arc<Carrier>) -> Result<Link, String> {
    let link = LinkId::random(&mut OsEntropy).map_err(|e| e.to_string())?;
    let hello = carrier.knock(&link).await?;
    carrier.knocked(&hello, DOOR_WAIT).await?;
    Ok(carry(carrier, link, Way::Up))
}

/// A node's link: the next client's hello, within [`DOOR_WAIT`], then the
/// down way sent and the up way read.
pub async fn accept(carrier: Arc<Carrier>) -> Result<Link, String> {
    let link = carrier.answer(DOOR_WAIT).await?;
    Ok(carry(carrier, link, Way::Down))
}

/// What `from` gives into `buf` within [`GATHER`] of each read, until `buf`
/// is full, `from` ends, or nothing more comes: never a wait on the layer
/// once a piece has its first byte.
async fn gather<R: AsyncRead + Unpin>(from: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match tokio::time::timeout(GATHER, from.read(&mut buf[got..])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => got += read,
            Ok(Err(e)) => return Err(e),
        }
    }
    Ok(got)
}

/// A task that carries the pipe's far end: `send`'s pieces from the layer,
/// and the other way's into it.
pub fn carry(carrier: Arc<Carrier>, link: LinkId, send: Way) -> Link {
    let (ours, far) = tokio::io::duplex(PIPE);
    let task = tokio::spawn(async move {
        let (mut from_layer, mut to_layer) = tokio::io::split(far);
        // This end's writes speed the polls of its reads.
        let wrote = Notify::new();
        let room = carrier.room().min(PIECE_MOST - 1);
        // True when the layer ended its bytes, which ends this way cleanly.
        let up = async {
            let mut buf = vec![0u8; PIECE_MOST];
            for n in 0u64.. {
                // The first byte, then what came at once, up to one byte
                // past a note's room: a note goes now.
                let mut first = [0u8; 1];
                let read = match from_layer.read(&mut first).await {
                    Ok(0) => 0,
                    Ok(_) => {
                        buf[0] = first[0];
                        let mut got = match gather(&mut from_layer, &mut buf[1..=room]).await {
                            Ok(more) => 1 + more,
                            Err(_) => return false,
                        };
                        if got > room {
                            // A piece: its host's pace, then what came.
                            carrier.ready(PIECE_MOST).await;
                            match gather(&mut from_layer, &mut buf[got..]).await {
                                Ok(more) => got += more,
                                Err(_) => return false,
                            }
                        }
                        got
                    }
                    Err(_) => return false,
                };
                if carrier.send(send, &link, n, &buf[..read]).await.is_err() {
                    return false;
                }
                wrote.notify_one();
                if read == 0 {
                    return true;
                }
            }
            false
        };
        let down = async {
            for n in 0u64.. {
                match carrier.receive_nudged(send.other(), &link, n, PIECE_WAIT, Some(&wrote)).await {
                    Ok(bytes) if !bytes.is_empty() => {
                        if to_layer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    _ => break,
                }
            }
            let _ = to_layer.shutdown().await;
        };
        tokio::pin!(down);
        // A way that failed ends the link; the layer's own end leaves the far
        // end's last pieces to come.
        let clean = tokio::select! {
            clean = up => clean,
            () = &mut down => return,
        };
        if clean {
            down.await;
        }
    });
    Link { io: ours, task: task.abort_handle(), id: link }
}
