//! One routed connection of a Tox TCP relay as a stream of bytes (T-734):
//! each end asks the relay to route to the other's key, and once the relay
//! says that both asked (`connected`), the connection's data packets carry
//! the stream. c-toxcore's relay holds no more than a short queue for a
//! client and stops passing a connection that sends faster than its peer
//! reads (measured, the test: a MiB stalled after 100 to 230 kB in half the
//! runs), so the stream keeps its own order and pace inside the packets
//! ([`crate::packet_stream`]): at most [`WINDOW`] bytes in flight, sent again
//! when nothing moved for [`AGAIN`]. The relay's pings are answered; its
//! `disconnected` ends the stream. The relay sees each byte: the end-to-end
//! channel above it keeps them from it.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::mpsc;

use super::wire::{Packet, Receiver, Sender, KEY};
use crate::packet_stream::{self, In, Packets, Shape};

/// The bytes of one data packet's part of the stream.
pub const CHUNK: usize = 1200;
/// The most bytes in flight, unsaid by the receiver.
pub const WINDOW: u64 = 32 * 1024;
/// With nothing said for this long, the bytes in flight go again.
pub const AGAIN: Duration = Duration::from_millis(1000);
/// The stream's shape on a relay's routed connection.
pub const SHAPE: Shape = Shape { chunk: CHUNK, window: WINDOW, again: AGAIN };

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
    // A packet's read is no point to cancel at: it reads on its own.
    let (packets, incoming) = mpsc::channel::<io::Result<In<Packet>>>(64);
    tokio::spawn(async move {
        loop {
            let got = receiver.recv().await;
            let end = got.is_err();
            let item = got.map(|packet| match packet {
                Packet::Data { id: from, data } if from == id => In::Data(data),
                other => In::Other(other),
            });
            if packets.send(item).await.is_err() || end {
                break;
            }
        }
    });
    Ok(packet_stream::stream(Route { sender, id }, incoming, SHAPE))
}

/// The routed connection `id`, as the stream sends on it.
struct Route<W> {
    sender: Sender<W>,
    id: u8,
}

impl<W: AsyncWrite + Unpin + Send + 'static> Packets for Route<W> {
    type Other = Packet;

    async fn send(&mut self, payload: Vec<u8>) -> io::Result<()> {
        self.sender.data(self.id, &payload).await
    }

    async fn other(&mut self, packet: Packet) -> io::Result<bool> {
        match packet {
            Packet::Ping(ping) => self.sender.pong(ping).await.map(|()| true),
            Packet::Disconnected(gone) => Ok(gone != self.id),
            _ => Ok(true),
        }
    }
}
