//! One routed connection of a Tox TCP relay as a stream of bytes (T-734):
//! each end asks the relay to route to the other's key, and once the relay
//! says that both asked (`connected`), the connection's data packets carry
//! the stream. c-toxcore's relay holds no more than a short queue for a
//! client and stops passing a connection that sends faster than its peer
//! reads (measured, the test: a MiB stalled after 100 to 230 kB in half the
//! runs), so the stream keeps its own order and pace inside the packets:
//! each data packet carries its offset, the receiver says the next offset
//! that it waits for, the sender keeps [`WINDOW`] bytes in flight at most
//! and sends again from the last said offset when nothing moved for
//! [`AGAIN`]. The relay's pings are answered; its `disconnected` ends the
//! stream. The relay sees each byte: the end-to-end channel above it keeps
//! them from it.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use super::wire::{Packet, Receiver, Sender, KEY};

/// The bytes of one data packet's part of the stream.
pub const CHUNK: usize = 1200;
/// The most bytes in flight, unsaid by the receiver.
pub const WINDOW: u64 = 32 * 1024;
/// With nothing said for this long, the bytes in flight go again.
pub const AGAIN: Duration = Duration::from_millis(1000);
/// The receiver says where it is at least each this many packets.
const SAY_EVERY: u32 = 4;
/// What a stream holds between the relay and its reader.
const BUFFER: usize = 256 * 1024;

/// The stream's own kinds, the first byte of a data packet's payload.
const DATA: u8 = 0;
const SAID: u8 = 1;
const FIN: u8 = 2;

/// Route to `peer` and wait, within `limit`, until the relay connects the
/// two: the stream of the routed connection.
pub async fn meet<R, W>(
    mut sender: Sender<W>,
    mut receiver: Receiver<R>,
    peer: [u8; KEY],
    limit: Duration,
) -> io::Result<DuplexStream>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    sender.route(&peer).await?;
    let waited = tokio::time::timeout(limit, async {
        let mut routed = None;
        loop {
            match receiver.recv().await? {
                Packet::Routed { id: 0, key } if key == peer => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "the relay refused the route"));
                }
                Packet::Routed { id, key } if key == peer => {
                    routed = Some(id);
                }
                Packet::Connected(id) if Some(id) == routed => return Ok(id),
                Packet::Ping(ping) => sender.pong(ping).await?,
                _ => {}
            }
        }
    })
    .await;
    let id = match waited {
        Ok(found) => found?,
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "the peer did not come to the relay in time")),
    };
    let (near, far) = tokio::io::duplex(BUFFER);
    // A packet's read is no point to cancel at: it reads on its own.
    let (packets, incoming) = mpsc::channel::<io::Result<Packet>>(64);
    tokio::spawn(async move {
        loop {
            let got = receiver.recv().await;
            let end = got.is_err();
            if packets.send(got).await.is_err() || end {
                break;
            }
        }
    });
    tokio::spawn(run(sender, incoming, id, far));
    Ok(near)
}

/// The stream's state at one end.
struct Stream {
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

async fn run<W: AsyncWrite + Unpin>(
    mut sender: Sender<W>,
    mut incoming: mpsc::Receiver<io::Result<Packet>>,
    id: u8,
    far: DuplexStream,
) {
    let (mut far_read, mut far_write) = tokio::io::split(far);
    let mut s = Stream { flight: VecDeque::new(), said: 0, next: 0, fin: None, expected: 0, unsaid: 0, peer_fin: None };
    let mut buf = vec![0u8; CHUNK];
    let mut last_move = tokio::time::Instant::now();
    let mut write_closed = false;
    loop {
        let room = s.fin.is_none() && s.next - s.said < WINDOW;
        let pending = s.next > s.said || s.fin.is_some_and(|end| s.said < end);
        let timer = tokio::time::sleep_until(last_move + AGAIN);
        tokio::select! {
            got = incoming.recv() => {
                let Some(Ok(packet)) = got else { break };
                match packet {
                    Packet::Data { id: from, data } if from == id => {
                        if take(&mut sender, id, &mut s, &data, &mut far_write, &mut write_closed, &mut last_move)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // What this end got gets said once nothing more waits.
                        if s.unsaid > 0 && incoming.is_empty() {
                            s.unsaid = 0;
                            if say(&mut sender, id, s.expected).await.is_err() {
                                break;
                            }
                        }
                    }
                    Packet::Ping(ping) => {
                        if sender.pong(ping).await.is_err() {
                            break;
                        }
                    }
                    Packet::Disconnected(gone) if gone == id => break,
                    _ => {}
                }
            }
            read = far_read.read(&mut buf), if room => {
                match read {
                    Ok(0) | Err(_) => {
                        s.fin = Some(s.next);
                        last_move = tokio::time::Instant::now();
                        if send_fin(&mut sender, id, s.next).await.is_err() {
                            break;
                        }
                    }
                    Ok(n) => {
                        if s.next == s.said {
                            last_move = tokio::time::Instant::now();
                        }
                        s.flight.extend(&buf[..n]);
                        if send_data(&mut sender, id, s.next, &buf[..n]).await.is_err() {
                            break;
                        }
                        s.next += n as u64;
                    }
                }
            }
            () = timer, if pending => {
                last_move = tokio::time::Instant::now();
                // Nothing moved: what is in flight goes again, from the said offset.
                if again(&mut sender, id, &s).await.is_err() {
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
async fn take<W: AsyncWrite + Unpin, F: AsyncWrite + Unpin>(
    sender: &mut Sender<W>,
    id: u8,
    s: &mut Stream,
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
                say(sender, id, s.expected).await?;
            }
        }
        // Out of order, or again: say where this end is, so the peer goes on from there.
        DATA => say(sender, id, s.expected).await?,
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
            say(sender, id, s.expected).await?;
        }
        _ => {}
    }
    if s.peer_fin.is_some_and(|end| s.expected >= end) && !*write_closed {
        let _ = far_write.shutdown().await;
        *write_closed = true;
    }
    Ok(())
}

async fn say<W: AsyncWrite + Unpin>(sender: &mut Sender<W>, id: u8, offset: u64) -> io::Result<()> {
    let mut packet = vec![SAID];
    packet.extend_from_slice(&offset.to_be_bytes());
    sender.data(id, &packet).await
}

async fn send_data<W: AsyncWrite + Unpin>(sender: &mut Sender<W>, id: u8, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut packet = Vec::with_capacity(9 + bytes.len());
    packet.push(DATA);
    packet.extend_from_slice(&offset.to_be_bytes());
    packet.extend_from_slice(bytes);
    sender.data(id, &packet).await
}

async fn send_fin<W: AsyncWrite + Unpin>(sender: &mut Sender<W>, id: u8, end: u64) -> io::Result<()> {
    let mut packet = vec![FIN];
    packet.extend_from_slice(&end.to_be_bytes());
    sender.data(id, &packet).await
}

/// The bytes in flight, again from the said offset, then the FIN when it
/// was sent and is not said.
async fn again<W: AsyncWrite + Unpin>(sender: &mut Sender<W>, id: u8, s: &Stream) -> io::Result<()> {
    let flight: Vec<u8> = s.flight.iter().copied().collect();
    let mut offset = s.said;
    for chunk in flight.chunks(CHUNK) {
        send_data(sender, id, offset, chunk).await?;
        offset += chunk.len() as u64;
    }
    if let Some(end) = s.fin.filter(|end| s.said < *end || s.flight.is_empty()) {
        send_fin(sender, id, end).await?;
    }
    Ok(())
}
