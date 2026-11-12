//! A link of the road: a byte stream for the resumable layer, made of an
//! end's two ways, a POST of each frame to its own channel and the stream of
//! the far end's channel. Each way begins with its mark, frame 0, which the
//! reader checks before the layer reads a byte. A frame waits for smee.io's
//! `200` before the next goes, as two POSTs in flight may reach the readers
//! in either order; a frame whose number is not the next one, a stranger's
//! event, or a stream that ends or goes quiet ends the link, and the layer
//! goes on with a new one and sends again what the far end missed.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::AbortHandle;

use super::frame::{self, Message, FRAME_MAX};
use super::http::{Events, Http};
use super::names::Ends;
pub use crate::piping::flow::Opening;
use crate::piping::paths::same;

/// How long a stream may take to give smee.io's `ready`, which it writes at
/// once: a stream with no event this long is held on the way.
pub const READY_LIMIT: Duration = Duration::from_secs(15);
/// How long one end waits for the far end's mark.
pub const MARK_LIMIT: Duration = Duration::from_secs(15);
/// How long a POST may take to be answered.
pub const POST_LIMIT: Duration = Duration::from_secs(30);
/// A stream with no event this long is gone: smee.io pings each 30 s.
pub const IDLE_LIMIT: Duration = Duration::from_secs(75);
/// Each direction of the pipe between the layer and a link's ways.
pub const PIPE: usize = 512 * 1024;

/// The name of smee.io's first event on a stream.
const READY: &str = "ready";
/// The name of an event of a POST, which has none of its own.
const MESSAGE: &str = "message";

/// A link: the layer's end of a pipe whose far end a task carries over the
/// link's two ways. Dropping it ends the task, and the ways with it.
pub struct Link {
    io: DuplexStream,
    task: AbortHandle,
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

/// The stream of `channel`, once smee.io's `ready` came on it: a proxy that
/// holds an answer until its end gives no event, and the road is no road
/// through it.
pub async fn open_stream(http: &Http, channel: &str) -> Result<Events, Opening> {
    let mut events = http.stream(channel, READY_LIMIT).await.map_err(|failed| Opening::Failed(failed.to_string()))?;
    let held = || {
        Opening::Held(format!(
            "no event of smee.io's stream within {} s: a proxy on the way may hold a streamed answer until its end",
            READY_LIMIT.as_secs()
        ))
    };
    match tokio::time::timeout(READY_LIMIT, events.next(READY_LIMIT)).await {
        Ok(Ok(Some(event))) if event.name == READY => Ok(events),
        // Another event before `ready`: not smee.io's stream.
        Ok(Ok(Some(_))) => Err(Opening::Failed("a stream that did not begin with smee.io's ready".into())),
        Ok(Ok(None)) => Err(Opening::Failed("the stream ended before smee.io's ready".into())),
        Ok(Err(_)) | Err(_) => Err(held()),
    }
}

/// POST this end's mark, frame 0 of its way.
pub async fn send_mark(http: &Http, ends: &Ends) -> Result<(), Opening> {
    let body = frame::frame(0, &ends.mine);
    http.post(&ends.send, &body, POST_LIMIT).await.map_err(|failed| Opening::Failed(format!("the mark: {failed}")))
}

/// The far end's mark, the first frame of `events`, checked within `limit`.
/// Pings and hellos are passed over; this end's own mark says that its two
/// ways share a channel, which the reader names.
pub async fn read_mark(events: &mut Events, ends: &Ends, limit: Duration) -> Result<(), Opening> {
    let reading = async {
        loop {
            let event = match events.next(IDLE_LIMIT).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(Opening::Failed("the far end's stream ended before its mark".into())),
                Err(why) => return Err(Opening::Failed(format!("the far end's stream: {why}"))),
            };
            if event.name != MESSAGE {
                continue;
            }
            return match frame::read(&event.data) {
                Ok(Message::Frame(0, mark)) => check_mark(&mark, ends),
                Ok(Message::Hello(_)) => continue,
                Ok(Message::Frame(n, _)) => Err(Opening::Failed(format!("frame {n} before the far end's mark"))),
                Err(why) => Err(Opening::Failed(why)),
            };
        }
    };
    match tokio::time::timeout(limit, reading).await {
        Ok(read) => read,
        Err(_) => Err(Opening::Failed(format!("no mark of the far end within {} s", limit.as_secs()))),
    }
}

/// Whether `got`, the first frame of the far end's way, is its mark.
pub fn check_mark(got: &[u8], ends: &Ends) -> Result<(), Opening> {
    if same(got, &ends.theirs) {
        return Ok(());
    }
    if same(got, &ends.mine) {
        let why = "this end read its own mark: both ways of the link are on one channel, so each end reads its own \
                   frames";
        return Err(Opening::Failed(why.into()));
    }
    let why = "the far end's way began with another mark: not this link's far end, or one that took the wrong way";
    Err(Opening::Failed(why.into()))
}

/// The link, once both marks went: a task that carries the pipe's far end
/// over the two ways, the layer's bytes into numbered POSTs of at most
/// `size` bytes each, and the far end's frames, in their order, into the
/// layer. A POST refused as too large (413) halves `size` for the next link.
pub fn carry(http: Arc<Http>, ends: &Ends, mut events: Events, size: Arc<AtomicUsize>) -> Link {
    let (ours, far) = tokio::io::duplex(PIPE);
    let send = ends.send.clone();
    let task = tokio::spawn(async move {
        let (mut from_layer, mut to_layer) = tokio::io::split(far);
        // True when the layer ended its bytes, which leaves the far end's last
        // bytes to come.
        let up = async {
            let mut buf = vec![0u8; FRAME_MAX];
            let mut n: u64 = 1;
            loop {
                let max = size.load(Ordering::SeqCst).clamp(frame::FRAME_MIN, FRAME_MAX);
                match from_layer.read(&mut buf[..max]).await {
                    Ok(0) => return true,
                    Ok(k) => match http.post(&send, &frame::frame(n, &buf[..k]), POST_LIMIT).await {
                        Ok(()) => n += 1,
                        Err(failed) => {
                            if failed.status == Some(413) {
                                size.store(frame::halved(max), Ordering::SeqCst);
                            }
                            return false;
                        }
                    },
                    Err(_) => return false,
                }
            }
        };
        let down = async {
            let mut want: u64 = 1;
            loop {
                let event = match events.next(IDLE_LIMIT).await {
                    Ok(Some(event)) => event,
                    _ => break,
                };
                if event.name != MESSAGE {
                    continue;
                }
                match frame::read(&event.data) {
                    Ok(Message::Frame(n, bytes)) if n == want => {
                        want += 1;
                        if to_layer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    // A frame missed, twice, or out of its order, or a
                    // stranger's event: the layer repairs it on a new link.
                    _ => break,
                }
            }
            let _ = to_layer.shutdown().await;
        };
        tokio::pin!(down);
        let clean = tokio::select! {
            clean = up => clean,
            () = &mut down => return,
        };
        if clean {
            down.await;
        }
    });
    Link { io: ours, task: task.abort_handle() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smee::names::{LinkId, Secret};

    #[test]
    fn a_mark_is_checked_and_one_s_own_says_that_the_two_ways_share_a_channel() {
        let secret = Secret::from_bytes([3; 32]);
        let link = LinkId([5; 16]);
        let (client, node) = (Ends::client(&secret, &link), Ends::node(&secret, &link));
        assert_eq!(check_mark(&node.mine, &client), Ok(()));
        assert_eq!(check_mark(&client.mine, &node), Ok(()));
        // The planted defect of T-741: both ways on one channel.
        let one = Ends { recv: client.send.clone(), ..client.clone() };
        let read_back = check_mark(&one.mine, &one).unwrap_err().to_string();
        assert!(read_back.contains("read its own mark") && read_back.contains("one channel"), "{read_back}");
        let stranger = check_mark(&[0; 16], &client).unwrap_err().to_string();
        assert!(stranger.contains("another mark"), "{stranger}");
    }
}
