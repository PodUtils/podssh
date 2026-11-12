//! The packets of a tunnel over HTTP/3, both ways: each IP packet in one
//! QUIC datagram (RFC 9297), with no TCP under the stack's TCP; and the
//! request stream's capsules, read for ADDRESS_ASSIGN (a server of RFC 9484
//! gives the client its address so) and for a packet that a server sent as
//! a DATAGRAM capsule. A packet larger than a datagram can carry is dropped,
//! as a full link drops one; the stack's MTU is set below that room.

use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use pod_quic::noq::{Connection, Endpoint, RecvStream, SendDatagramError, SendStream};
use podssh_ws::hysteria::h3 as http3;
use tokio::sync::{mpsc, watch};

use super::open::{frame, Opened};
use super::wire;
use crate::capsule;
use crate::flow::Flow;
use crate::stack::{Link, Why};

/// Packets that wait between the stack and the tunnel's tasks.
const PACKETS: usize = 256;
/// The longest DATA frame of the request stream that podssh reads.
const MOST_DATA: u64 = capsule::MAX_CAPSULE + 16;

/// The link of an opened tunnel whose request stream is `opened`, on
/// `endpoint`, which the link holds: noq's endpoint drives the connection.
/// The addresses that the server assigns come on the watch it gives.
pub fn link(
    endpoint: Endpoint,
    connection: Connection,
    opened: Opened,
    why: Why,
) -> (Link, watch::Receiver<Vec<(IpAddr, u8)>>) {
    let Opened { send, recv, control, uni } = opened;
    let stream_id = u64::from(recv.id());
    let (to_stack, inbound) = mpsc::channel(PACKETS);
    let (out, from_stack) = mpsc::channel(PACKETS);
    let (assign, assigned) = watch::channel(Vec::new());
    let flow = Arc::new(Flow::default());
    let datagrams = tokio::spawn(read(connection.clone(), stream_id, to_stack.clone(), why.clone(), flow.clone()));
    let capsules = tokio::spawn(capsules(recv, stream_id, to_stack, assign, why.clone(), flow.clone()));
    let writer = tokio::spawn(write(connection.clone(), stream_id, from_stack, why.clone(), flow.clone()));
    let held = tokio::spawn(hold(endpoint, connection, send, control, why.clone()));
    let tasks =
        vec![datagrams.abort_handle(), capsules.abort_handle(), writer.abort_handle(), held.abort_handle(), uni];
    (Link { out, inbound, why, tasks, flow }, assigned)
}

/// The datagrams of the connection, to the stack.
async fn read(connection: Connection, stream_id: u64, to_stack: mpsc::Sender<Vec<u8>>, why: Why, flow: Arc<Flow>) {
    loop {
        let datagram = tokio::select! {
            datagram = connection.read_datagram() => datagram,
            () = why.ended() => return,
        };
        let datagram = match datagram {
            Ok(datagram) => datagram,
            Err(e) => return why.set(format!("the QUIC connection ended: {e}")),
        };
        flow.came(datagram.len());
        match wire::packet_of(stream_id, &datagram) {
            Ok(Some(packet)) if !packet.is_empty() => {
                if to_stack.send(packet.to_vec()).await.is_err() {
                    return;
                }
                flow.handed_in();
            }
            // Another request's, another context's, or an empty one.
            Ok(_) => {}
            Err(e) => return why.set(format!("the server sent {e}")),
        }
    }
}

/// The request stream's DATA, as capsules: the addresses of ADDRESS_ASSIGN
/// to `assign`, a DATAGRAM capsule's packet to the stack; the stream's end
/// ends the tunnel.
async fn capsules(
    mut recv: RecvStream,
    stream_id: u64,
    to_stack: mpsc::Sender<Vec<u8>>,
    assign: watch::Sender<Vec<(IpAddr, u8)>>,
    why: Why,
    flow: Arc<Flow>,
) {
    let mut reader = capsule::Reader::default();
    loop {
        let next = tokio::select! {
            next = frame(&mut recv, MOST_DATA) => next,
            () = why.ended() => return,
        };
        let payload = match next {
            Ok(Some((http3::DATA, payload))) => payload,
            // Trailers, or a frame of a type that podssh does not know.
            Ok(Some(_)) => continue,
            Ok(None) => return why.set("the server ended the tunnel's request stream"),
            Err(e) => return why.set(format!("the tunnel's request stream: {e}")),
        };
        reader.push(&payload);
        loop {
            let capsule = match reader.next_capsule() {
                Ok(Some(capsule)) => capsule,
                Ok(None) => break,
                Err(e) => return why.set(e),
            };
            match capsule.kind {
                wire::ADDRESS_ASSIGN => match wire::assigned(&capsule.payload) {
                    Ok(addresses) => {
                        assign.send_replace(addresses);
                    }
                    Err(e) => return why.set(format!("the server sent {e}")),
                },
                capsule::DATAGRAM => {
                    // Over HTTP/3 a DATAGRAM capsule holds an HTTP Datagram's
                    // payload: the Context ID, then the packet (RFC 9297,
                    // section 3.5), with no Quarter Stream ID.
                    let mut whole = Vec::with_capacity(capsule.payload.len() + 8);
                    capsule::put_varint(&mut whole, stream_id / 4);
                    whole.extend_from_slice(&capsule.payload);
                    flow.came(whole.len());
                    if let Ok(Some(packet)) = wire::packet_of(stream_id, &whole) {
                        if !packet.is_empty() && to_stack.send(packet.to_vec()).await.is_err() {
                            return;
                        }
                        flow.handed_in();
                    }
                }
                // ROUTE_ADVERTISEMENT and the rest: the stack routes each
                // address to the tunnel, its only link.
                _ => {}
            }
        }
    }
}

/// The stack's packets, each in a datagram; the send waits for room in
/// noq's buffer rather than drop the oldest.
async fn write(
    connection: Connection,
    stream_id: u64,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
    why: Why,
    flow: Arc<Flow>,
) {
    while let Some(packet) = from_stack.recv().await {
        flow.taken_out();
        let datagram = Bytes::from(wire::datagram(stream_id, &packet));
        let len = datagram.len();
        flow.wait(true);
        let sent = connection.send_datagram_wait(datagram).await;
        flow.wait(false);
        match sent {
            Ok(()) => flow.sent(len),
            // Larger than the path takes now: dropped, as a link drops it.
            Err(SendDatagramError::TooLarge) => {}
            Err(e) => return why.set(format!("the tunnel's datagrams: {e}")),
        }
    }
}

/// The endpoint, the request's sending half and the control stream, held
/// open while the tunnel lasts; at its end the connection closes with
/// H3_NO_ERROR.
async fn hold(_endpoint: Endpoint, connection: Connection, _send: SendStream, _control: SendStream, why: Why) {
    tokio::select! {
        e = connection.closed() => why.set(format!("the QUIC connection closed: {e}")),
        () = why.ended() => connection.close(pod_quic::noq::VarInt::from_u32(0x100), b""),
    }
}

// The longest DATA frame holds the longest capsule and its head: checked
// when the crate builds.
const _: () = assert!(MOST_DATA > crate::capsule::MAX_CAPSULE + 8);
