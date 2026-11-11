//! The two ends of a pair's road (T-733) on a wire that the caller dials:
//! the TCP relay of ZeroTier Inc. through `HTTPS_PROXY`, or a test's own.
//! The node holds a member of the pair's network at the node's identity,
//! and gives each connection to its port to the caller; when the wire ends
//! it dials again, with a backoff. A client joins with an identity made for
//! its run and connects to the node's 6plane address; its link holds the
//! member, which ends with it.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_warp::stream::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::member::{sixplane, Member, State, Wire};
use crate::pair::PairRoad;

/// A byte stream of the wire.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A dial of the wire in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<Wire, String>> + Send>>;
/// How an end reaches the wire, each time.
pub type Dial = Arc<dyn Fn() -> Dialing + Send + Sync>;
/// Where an end's lines go.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The bound of a client's connection to the node: the roots' WHOIS and the
/// path through the relay took 30 s in the live run.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(60);
/// The longest wait before the node dials again.
const MOST_WAIT: Duration = Duration::from_secs(60);
/// A member that lived this long ended as a lost connection does: the next
/// dial is made at once.
const LIVED: Duration = Duration::from_secs(60);

/// The wire of the TCP relay on `stream`.
pub fn relay_wire<S: Io>(stream: S) -> Wire {
    crate::relay::carry(stream, crate::version())
}

/// The node's address and port inside the pair's network.
pub fn node_at(road: &PairRoad) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(sixplane(road.nwid, road.node)), road.port)
}

/// The node of the road: for ever, each connection to its port goes to
/// `visitors` with the far address; it returns once `visitors` is closed.
pub async fn serve(road: PairRoad, dial: Dial, visitors: mpsc::Sender<(Stream, String)>, say: Say) {
    let mut retry = 0u32;
    while !visitors.is_closed() {
        let began = tokio::time::Instant::now();
        match held(&road, &dial, &visitors, &say).await {
            Ok(why) => say(format!("ZeroTier's road ended ({why}); it is made again")),
            Err(why) => say(format!("ZeroTier's road: {why}")),
        }
        retry = if began.elapsed() >= LIVED { 0 } else { retry.saturating_add(1) };
        tokio::time::sleep(backoff(retry)).await;
    }
}

/// One member of the node, until its wire ends; why it ended.
async fn held(
    road: &PairRoad,
    dial: &Dial,
    visitors: &mpsc::Sender<(Stream, String)>,
    say: &Say,
) -> Result<String, String> {
    let wire = dial().await?;
    let identity = Some(road.node_identity().as_bytes().to_vec());
    let state = Arc::new(Mutex::new(State { identity, planet: road.planet.clone(), ..State::default() }));
    let member = Member::start(state, wire, Some(road.nwid))?;
    let stack = member.stack.as_ref().ok_or("the member joined no network")?;
    let at = node_at(road);
    let mut listener = stack.listen(at)?;
    say(format!("ZeroTier's road: the node waits at [{}]:{} on the network {:016x}", at.ip(), at.port(), road.nwid));
    loop {
        tokio::select! {
            got = listener.accept() => match got {
                Ok(stream) => {
                    if visitors.send((stream, format!("{at} on ZeroTier"))).await.is_err() {
                        return Ok("the node ended".into());
                    }
                }
                Err(why) => return Ok(why),
            },
            () = stack.closed() => return Ok(stack.ended().unwrap_or_else(|| "the wire ended".into())),
        }
    }
}

/// The wait before the dial after `retry` failures: 1 s, doubled, at most
/// a minute.
fn backoff(retry: u32) -> Duration {
    match retry {
        0 => Duration::ZERO,
        n => Duration::from_secs(1u64 << n.min(6).saturating_sub(1)).min(MOST_WAIT),
    }
}

/// A client's link to the node, which holds its member.
pub struct Link {
    stream: Stream,
    _member: Member,
}

/// A client's link to the node of `road`, on a wire of `dial`, open within
/// `limit`.
pub async fn link(road: &PairRoad, dial: &Dial, limit: Duration) -> Result<Link, String> {
    let wire = dial().await?;
    let state = State { planet: road.planet.clone(), ..State::default() };
    let member = Member::start(Arc::new(Mutex::new(state)), wire, Some(road.nwid))?;
    let stack = member.stack.as_ref().ok_or("the member joined no network")?;
    let stream = connect(stack, node_at(road), limit).await?;
    Ok(Link { stream, _member: member })
}

/// A TCP connection to `to` on `stack`, within `limit`, in short tries, each
/// with a fresh SYN: the first SYNs are lost while the core finds the far
/// member through the roots, and one try's own backoff would send its next
/// SYN 30 s and more later (a live run linked at 31.8 s, the SYN of second 31).
pub async fn connect(stack: &podssh_warp::stack::Stack, to: SocketAddr, limit: Duration) -> Result<Stream, String> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let (began, left) =
            (tokio::time::Instant::now(), deadline.saturating_duration_since(tokio::time::Instant::now()));
        match stack.connect(to, left.min(TRY)).await {
            Ok(stream) => return Ok(stream),
            Err(why) if stack.ended().is_some() => return Err(why),
            Err(_) if left > TRY => {
                // A try that failed at once (a reset) waits out its second.
                tokio::time::sleep(Duration::from_secs(1).saturating_sub(began.elapsed())).await;
            }
            Err(_) => return Err(format!("{to}: no answer inside the network within {} s", limit.as_secs())),
        }
    }
}

/// The bound of one try of a client's connection to the node.
const TRY: Duration = Duration::from_secs(4);

impl AsyncRead for Link {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "road_tests.rs"]
mod tests;
