//! HTTP/3 on an open QUIC connection, as connect-ip-go's `Dial` speaks it:
//! the client's control stream with its SETTINGS; the server's control
//! stream and its SETTINGS, which must allow HTTP Datagrams; one request
//! stream with the extended CONNECT; and the answer's status. The server's
//! other streams of one way (QPACK's, which podssh never needs, as it
//! offers no dynamic table) are read and dropped while the tunnel lasts; a
//! control stream that ends ends the tunnel (RFC 9114, section 6.2.1).

use std::time::Duration;

use pod_quic::noq::{Connection, RecvStream, SendStream};
use podssh_ws::hysteria::h3 as http3;
use tokio::sync::oneshot;

use super::wire::{self, Peer};
use super::Failed;
use crate::stack::Why;

/// The longest frame that podssh reads before the answer, and the longest
/// SETTINGS.
const MOST_FRAME: u64 = 64 * 1024;
/// QPACK's encoder and decoder streams (RFC 9204, section 4.2).
const QPACK_ENCODER: u64 = 0x02;
const QPACK_DECODER: u64 = 0x03;

/// The request: what the CONNECT says, and whether the server must allow
/// the extended CONNECT before it is sent (RFC 9220, section 3). WARP's
/// edge does not say it, and usque sends all the same.
#[derive(Debug, Clone)]
pub struct Ask {
    pub authority: String,
    pub path: String,
    pub protocol: &'static str,
    pub needs_extended_connect: bool,
    /// The draft's setting of datagrams beside the RFC's, for WARP's edge.
    pub draft_datagram: bool,
}

/// The tunnel's streams, once the server answered 2xx: the request's two
/// halves, the client's control stream (held open: closing it is an error
/// of the connection), and the task that reads the server's streams of one
/// way.
pub struct Opened {
    pub send: SendStream,
    pub recv: RecvStream,
    pub control: SendStream,
    pub uni: tokio::task::AbortHandle,
}

pub fn http3(e: impl std::fmt::Display) -> Failed {
    Failed::Http3(e.to_string())
}

/// A whole variable-length integer from `recv`; `None` at the stream's
/// clean end before its first byte.
pub async fn varint(recv: &mut RecvStream) -> Result<Option<u64>, Failed> {
    let mut bytes = [0u8; 8];
    match recv.read(&mut bytes[..1]).await.map_err(http3)? {
        None | Some(0) => return Ok(None),
        Some(_) => {}
    }
    let len = http3::varint_len(bytes[0]);
    recv.read_exact(&mut bytes[1..len]).await.map_err(http3)?;
    Ok(Some(http3::varint(&bytes[..len])))
}

/// One frame of `recv`: its type and payload, at most `most` bytes; `None`
/// at the stream's end.
pub async fn frame(recv: &mut RecvStream, most: u64) -> Result<Option<(u64, Vec<u8>)>, Failed> {
    let Some(kind) = varint(recv).await? else { return Ok(None) };
    let len = varint(recv).await?.ok_or_else(|| http3("a frame cut after its type"))?;
    if len > most {
        return Err(http3(format!("a frame of type {kind:#x} and {len} bytes, more than podssh reads ({most})")));
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload).await.map_err(http3)?;
    Ok(Some((kind, payload)))
}

/// The server's streams of one way, for as long as the connection lasts:
/// the control stream's SETTINGS go to `settings`, its end to `why`.
async fn server_streams(connection: Connection, settings: oneshot::Sender<Result<Peer, Failed>>, why: Why) {
    let mut settings = Some(settings);
    loop {
        let Ok(mut recv) = connection.accept_uni().await else { return };
        let Ok(Some(kind)) = varint(&mut recv).await else { continue };
        match kind {
            wire::CONTROL_STREAM => {
                let told = settings.take();
                let why = why.clone();
                tokio::spawn(async move {
                    let first = frame(&mut recv, MOST_FRAME).await;
                    let peer = match first {
                        Ok(Some((wire::SETTINGS, payload))) => wire::peer_settings(&payload).map_err(Failed::Http3),
                        Ok(Some((other, _))) => {
                            Err(http3(format!("the server's control stream began with {other:#x}")))
                        }
                        Ok(None) => Err(http3("the server's control stream ended before its SETTINGS")),
                        Err(e) => Err(e),
                    };
                    let failed = peer.is_err();
                    if let Some(told) = told {
                        let _ = told.send(peer);
                    }
                    if failed {
                        return;
                    }
                    // GOAWAY and the rest: read and dropped, until the end.
                    while let Ok(Some(_)) = frame(&mut recv, MOST_FRAME).await {}
                    why.set("the server closed HTTP/3's control stream");
                });
            }
            QPACK_ENCODER | QPACK_DECODER => {
                tokio::spawn(async move { while let Ok(Some(_)) = recv.read_chunk(4096).await {} });
            }
            // A stream of another type is not read (RFC 9114, section 6.2).
            _ => drop(recv),
        }
    }
}

/// The status of the answer: its first HEADERS frame's; a frame of an
/// unknown type before it is skipped, DATA before it is a broken answer.
async fn status(recv: &mut RecvStream) -> Result<u16, Failed> {
    loop {
        match frame(recv, MOST_FRAME).await? {
            None => return Err(http3("the request stream ended before the answer")),
            Some((http3::HEADERS, section)) => return http3::status(&section).map_err(http3),
            Some((http3::DATA, _)) => return Err(http3("a body before the answer's headers")),
            Some(_) => {}
        }
    }
}

/// HTTP/3 on `connection` and the CONNECT of `ask`, within `limit`.
pub async fn exchange(connection: &Connection, ask: &Ask, why: &Why, limit: Duration) -> Result<Opened, Failed> {
    let mut control = connection.open_uni().await.map_err(http3)?;
    control.write_all(&wire::control_stream(ask.draft_datagram)).await.map_err(http3)?;
    let (told, settings) = oneshot::channel();
    let uni = tokio::spawn(server_streams(connection.clone(), told, why.clone())).abort_handle();
    let asked = async {
        let peer = settings.await.map_err(|_| http3("the connection ended before the server's SETTINGS"))??;
        if !peer.datagrams {
            return Err(Failed::NoDatagrams);
        }
        if ask.needs_extended_connect && !peer.extended_connect {
            return Err(http3("the server's SETTINGS do not allow the extended CONNECT (RFC 9220)"));
        }
        let (mut send, mut recv) = connection.open_bi().await.map_err(http3)?;
        let section = wire::request(&ask.authority, &ask.path, ask.protocol);
        send.write_all(&http3::frame(http3::HEADERS, &section)).await.map_err(http3)?;
        let status = status(&mut recv).await?;
        if !(200..300).contains(&status) {
            return Err(Failed::Refused { status });
        }
        Ok((send, recv))
    };
    match tokio::time::timeout(limit, asked).await {
        Ok(Ok((send, recv))) => Ok(Opened { send, recv, control, uni }),
        Ok(Err(e)) => {
            uni.abort();
            Err(e)
        }
        Err(_) => {
            uni.abort();
            Err(Failed::Timeout("the server's answer to the CONNECT over HTTP/3"))
        }
    }
}
