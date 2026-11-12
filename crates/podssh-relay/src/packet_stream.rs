//! A byte stream over packets that a carrier may drop, hold back or carry
//! out of order (T-734's routed connection of a Tox relay, T-735's packets
//! of Yggdrasil's network): each data packet carries its offset, the
//! receiver says the next offset that it waits for, the sender keeps
//! [`Shape::window`] bytes in flight at most and sends again from the last
//! said offset when nothing moved for [`Shape::again`]. A FIN carries the
//! stream's length, so each direction ends on its own, as TCP's do. The
//! carrier's own packets (a relay's ping, its word that the peer left) go to
//! [`Packets::other`]. The end-to-end channel above it keeps the bytes from
//! whoever carries the packets.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

/// What a carrier gives the stream: one of its data packets' payload, or a
/// packet of its own.
pub enum In<E> {
    Data(Vec<u8>),
    Other(E),
}

/// A carrier of packets, as the stream sends on it.
pub trait Packets: Send + 'static {
    /// A packet of the carrier's own.
    type Other: Send + 'static;
    /// One packet of the stream to the peer.
    fn send(&mut self, payload: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
    /// A packet of the carrier's own: answered, and `Ok(false)` once it says
    /// that the stream is over.
    fn other(&mut self, packet: Self::Other) -> impl Future<Output = io::Result<bool>> + Send;
}

/// The stream's sizes and times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// The bytes of the stream in one packet.
    pub chunk: usize,
    /// The most bytes in flight, unsaid by the receiver.
    pub window: u64,
    /// With nothing said for this long, the bytes in flight go again.
    pub again: Duration,
}

/// The receiver says where it is at least each this many packets.
const SAY_EVERY: u32 = 4;
/// What a stream holds between the carrier and its reader.
const BUFFER: usize = 256 * 1024;
/// The stream's own kinds, the first byte of a packet.
const DATA: u8 = 0;
const SAID: u8 = 1;
const FIN: u8 = 2;

/// The stream over `packets`, which `incoming` feeds; it ends when either
/// end's FIN is said and the reader is done, or when the carrier ends.
pub fn stream<P: Packets>(
    packets: P,
    incoming: mpsc::Receiver<io::Result<In<P::Other>>>,
    shape: Shape,
) -> DuplexStream {
    let (near, far) = tokio::io::duplex(BUFFER);
    tokio::spawn(run(packets, incoming, shape, far));
    near
}

/// The stream's state at one end.
struct State {
    /// The bytes not yet said by the peer, from `said`.
    flight: VecDeque<u8>,
    said: u64,
    /// The next offset to send.
    next: u64,
    /// The local reader ended: the stream's length.
    fin: Option<u64>,
    /// The next offset that this end waits for, and the packets since it
    /// said so.
    expected: u64,
    unsaid: u32,
    /// The peer's length, once its FIN came.
    peer_fin: Option<u64>,
}

async fn run<P: Packets>(
    mut packets: P,
    mut incoming: mpsc::Receiver<io::Result<In<P::Other>>>,
    shape: Shape,
    far: DuplexStream,
) {
    let (mut far_read, mut far_write) = tokio::io::split(far);
    let mut s = State { flight: VecDeque::new(), said: 0, next: 0, fin: None, expected: 0, unsaid: 0, peer_fin: None };
    let mut buf = vec![0u8; shape.chunk];
    let mut last_move = tokio::time::Instant::now();
    let mut write_closed = false;
    loop {
        let room = s.fin.is_none() && s.next - s.said < shape.window;
        let pending = s.next > s.said || s.fin.is_some_and(|end| s.said < end);
        let timer = tokio::time::sleep_until(last_move + shape.again);
        tokio::select! {
            got = incoming.recv() => {
                let Some(Ok(packet)) = got else { break };
                match packet {
                    In::Data(data) => {
                        if take(&mut packets, &mut s, &data, &mut far_write, &mut write_closed, &mut last_move)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // What this end got gets said once nothing more waits.
                        if s.unsaid > 0 && incoming.is_empty() {
                            s.unsaid = 0;
                            if say(&mut packets, s.expected).await.is_err() {
                                break;
                            }
                        }
                    }
                    In::Other(other) => {
                        if !matches!(packets.other(other).await, Ok(true)) {
                            break;
                        }
                    }
                }
            }
            read = far_read.read(&mut buf), if room => {
                match read {
                    Ok(0) | Err(_) => {
                        s.fin = Some(s.next);
                        last_move = tokio::time::Instant::now();
                        if send(&mut packets, FIN, s.next, &[]).await.is_err() {
                            break;
                        }
                    }
                    Ok(n) => {
                        if s.next == s.said {
                            last_move = tokio::time::Instant::now();
                        }
                        s.flight.extend(&buf[..n]);
                        if send(&mut packets, DATA, s.next, &buf[..n]).await.is_err() {
                            break;
                        }
                        s.next += n as u64;
                    }
                }
            }
            () = timer, if pending => {
                last_move = tokio::time::Instant::now();
                // Nothing moved: what is in flight goes again, from the said offset.
                if again(&mut packets, &s, shape.chunk).await.is_err() {
                    break;
                }
            }
        }
        if s.fin.is_some_and(|end| s.said >= end) && write_closed {
            break;
        }
    }
    if !write_closed {
        let _ = far_write.shutdown().await;
    }
}

/// One data packet of the peer's: its bytes in order, what it says of this
/// end's, or its end.
async fn take<P: Packets, F: AsyncWrite + Unpin>(
    packets: &mut P,
    s: &mut State,
    data: &[u8],
    far_write: &mut F,
    write_closed: &mut bool,
    last_move: &mut tokio::time::Instant,
) -> io::Result<()> {
    let Some((&kind, rest)) = data.split_first() else { return Ok(()) };
    let Some(offset) = rest.get(..8).map(|b| u64::from_be_bytes(b.try_into().unwrap_or_default())) else {
        return Ok(());
    };
    match kind {
        DATA if offset == s.expected => {
            let bytes = &rest[8..];
            if !*write_closed && far_write.write_all(bytes).await.is_err() {
                *write_closed = true;
            }
            s.expected += bytes.len() as u64;
            s.unsaid += 1;
            if s.unsaid >= SAY_EVERY {
                s.unsaid = 0;
                say(packets, s.expected).await?;
            }
        }
        // Out of order, or again: say where this end is, so the peer goes on from there.
        DATA => say(packets, s.expected).await?,
        SAID if offset > s.said && offset <= s.next => {
            let drop = usize::try_from(offset - s.said).unwrap_or(usize::MAX);
            s.flight.drain(..drop.min(s.flight.len()));
            s.said = offset;
            *last_move = tokio::time::Instant::now();
        }
        // The FIN's own offset is the stream's length, past which nothing comes.
        SAID if s.fin == Some(offset) => s.said = offset,
        FIN => {
            s.peer_fin = Some(offset);
            say(packets, s.expected).await?;
        }
        _ => {}
    }
    if s.peer_fin.is_some_and(|end| s.expected >= end) && !*write_closed {
        let _ = far_write.shutdown().await;
        *write_closed = true;
    }
    Ok(())
}

async fn send<P: Packets>(packets: &mut P, kind: u8, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut packet = Vec::with_capacity(9 + bytes.len());
    packet.push(kind);
    packet.extend_from_slice(&offset.to_be_bytes());
    packet.extend_from_slice(bytes);
    packets.send(packet).await
}

async fn say<P: Packets>(packets: &mut P, offset: u64) -> io::Result<()> {
    send(packets, SAID, offset, &[]).await
}

/// The bytes in flight, again from the said offset, then the FIN when it
/// was sent and is not said.
async fn again<P: Packets>(packets: &mut P, s: &State, chunk: usize) -> io::Result<()> {
    let flight: Vec<u8> = s.flight.iter().copied().collect();
    let mut offset = s.said;
    for part in flight.chunks(chunk) {
        send(packets, DATA, offset, part).await?;
        offset += part.len() as u64;
    }
    if let Some(end) = s.fin.filter(|end| s.said < *end || s.flight.is_empty()) {
        send(packets, FIN, end, &[]).await?;
    }
    Ok(())
}
