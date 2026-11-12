//! Each stream of the tunnel as plain HTTP/1.1 on a pipe in this process:
//! the node serves the pipe as it serves a visitor of a tunnel of `ssh -R`
//! (`crate::ssh_http::visit`), so the relay role and the node's links take
//! hostc's visitors with no code of their own. An `OPEN` becomes the head of
//! a request ([`crate::quick::origin::Asked`], as the quick tunnel's origin
//! writes one), and the pipe's answer becomes `HEAD`, `DATA` and `END`
//! ([`super::bridge_http`]); a WebSocket's `OPEN` becomes its upgrade, and
//! its messages become frames on the pipe, both ways
//! ([`super::bridge_ws`]).
//!
//! The windows are the protocol's: a request's body comes in the window
//! that the node granted, and each byte is granted back only once the pipe
//! took it, so a role that does not read holds the server back and the
//! node holds at most one window; an answer's body goes only as far as the
//! server's grants, so a visitor that does not read holds the role back.
//! A WebSocket has no window: what waits for the role is counted, and past
//! [`super::MAX_QUEUED`] the stream closes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use super::link::Outbox;
use super::wire::{self, Kind, Open};
use super::{MAX_QUEUED, STREAM_WINDOW};
use crate::pinggy::far::Visitor;

/// The buffer of each pipe, each way.
pub const PIPE: usize = 64 * 1024;

/// What the server sent a stream.
#[derive(Debug)]
pub enum In {
    Data(Vec<u8>),
    Text(Vec<u8>),
    End(Vec<u8>),
    Reset,
    Window(u32),
}

/// What became of a frame that the socket gave a stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Given {
    Taken,
    /// The stream is gone: the socket forgets it.
    Ended,
    /// A WebSocket whose role does not read: closed with 1013.
    Overflow(u32),
}

/// A stream, as its socket holds it.
pub struct Stream {
    id: u32,
    websocket: bool,
    to: mpsc::UnboundedSender<In>,
    /// The bytes given and not yet taken by the pipe.
    queued: Arc<AtomicUsize>,
}

impl Stream {
    /// Give the stream a frame of `kind`. `Err` for a frame that breaks the
    /// protocol: a body past the window that the node granted, a `TEXT` of a
    /// request, a `WINDOW` of a WebSocket.
    pub fn give(&self, kind: Kind, payload: Vec<u8>) -> Result<Given, String> {
        let id = self.id;
        let given = match (kind, self.websocket) {
            (Kind::Data, false) => {
                let held = self.queued.load(Ordering::SeqCst) + payload.len();
                if held > STREAM_WINDOW {
                    return Err(format!("stream {id}: {held} bytes of a body past the window of {STREAM_WINDOW}"));
                }
                self.queued.fetch_add(payload.len(), Ordering::SeqCst);
                In::Data(payload)
            }
            (Kind::Data | Kind::Text, true) => {
                if self.queued.load(Ordering::SeqCst) + payload.len() > MAX_QUEUED {
                    return Ok(Given::Overflow(id));
                }
                self.queued.fetch_add(payload.len(), Ordering::SeqCst);
                match kind {
                    Kind::Data => In::Data(payload),
                    _ => In::Text(payload),
                }
            }
            (Kind::Text, false) => return Err(format!("stream {id}: a TEXT of a request")),
            (Kind::Window, false) => In::Window(wire::granted(&payload).map_err(|why| format!("stream {id}: {why}"))?),
            (Kind::Window, true) => return Err(format!("stream {id}: a WINDOW of a WebSocket")),
            (Kind::End, _) => In::End(payload),
            (Kind::Reset, _) => {
                let _ = self.to.send(In::Reset);
                return Ok(Given::Ended);
            }
            (Kind::Open | Kind::Head, _) => return Err(format!("stream {id}: an {kind:?} inside it")),
        };
        // A bridge that ended already lets the frame go, as the protocol says.
        Ok(match self.to.send(given) {
            Ok(()) => Given::Taken,
            Err(_) => Given::Ended,
        })
    }
}

/// What a bridge needs of its stream.
pub(super) struct Parts {
    pub id: u32,
    pub open: Open,
    /// The `Host` of a request that names none: the tunnel's name.
    pub name: String,
    pub pipe: tokio::io::DuplexStream,
    pub from: mpsc::UnboundedReceiver<In>,
    pub queued: Arc<AtomicUsize>,
    pub out: Outbox,
}

impl Parts {
    /// Abort the stream both ways, with `why`, which goes to the visitor.
    pub async fn reset(&self, why: &str) {
        let frame = wire::encode(Kind::Reset, self.id, why.as_bytes());
        let _ = self.out.send(super::link::Out::Frame(frame)).await;
    }

    /// Send a frame of the stream; false once the socket is gone.
    pub async fn send(&self, kind: Kind, payload: &[u8]) -> bool {
        self.out.send(super::link::Out::Frame(wire::encode(kind, self.id, payload))).await.is_ok()
    }

    /// The bytes that the pipe took: no longer held for the stream.
    pub fn taken(&self, bytes: usize) {
        self.queued.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// Who the visitor is, for the node's lines: the first address of the
/// `X-Forwarded-For` that the server passed, else the stream.
fn peer_of(open: &Open, id: u32) -> String {
    let first = open.header("x-forwarded-for").and_then(|v| v.split(',').next()).map(str::trim);
    match first.and_then(|text| text.parse::<std::net::IpAddr>().ok()) {
        Some(ip) => ip.to_string(),
        None => format!("hostc's stream {id}"),
    }
}

/// Start the stream `id` of `open`: its pipe goes to `visitors`, and its
/// bridge runs until it ends, then says so on `done`.
pub fn start(
    id: u32,
    open: Open,
    name: &str,
    out: Outbox,
    visitors: &mpsc::Sender<Visitor>,
    done: mpsc::UnboundedSender<u32>,
) -> Result<Stream, String> {
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let peer = peer_of(&open, id);
    // The node's queue of visitors is bounded: a full one refuses this one
    // alone, and the server answers its visitor.
    visitors
        .try_send(Visitor { stream: Box::new(theirs), peer })
        .map_err(|_| "the node takes no more visitors now".to_string())?;
    let (to, from) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    let websocket = open.websocket.is_some();
    let parts = Parts { id, open, name: name.to_string(), pipe: ours, from, queued: queued.clone(), out };
    tokio::spawn(async move {
        match websocket {
            true => super::bridge_ws::run(parts).await,
            false => super::bridge_http::run(parts).await,
        }
        let _ = done.send(id);
    });
    Ok(Stream { id, websocket, to, queued })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(websocket: bool) -> (Stream, mpsc::UnboundedReceiver<In>) {
        let (to, from) = mpsc::unbounded_channel();
        (Stream { id: 7, websocket, to, queued: Arc::new(AtomicUsize::new(0)) }, from)
    }

    #[test]
    fn a_body_past_the_window_that_the_node_granted_breaks_the_protocol() {
        let (http, _rx) = stream(false);
        assert_eq!(http.give(Kind::Data, vec![0; STREAM_WINDOW]), Ok(Given::Taken));
        let past = http.give(Kind::Data, vec![0; 1]).unwrap_err();
        assert!(past.contains("past the window"), "{past}");
        assert!(http.give(Kind::Text, b"x".to_vec()).is_err(), "a TEXT of a request");
        assert!(http.give(Kind::Window, vec![0, 0, 0, 0]).is_err(), "an empty grant");
    }

    #[test]
    fn a_websocket_that_its_role_does_not_read_closes_alone() {
        let (ws, _rx) = stream(true);
        assert_eq!(ws.give(Kind::Data, vec![0; MAX_QUEUED]), Ok(Given::Taken));
        assert_eq!(ws.give(Kind::Text, b"x".to_vec()), Ok(Given::Overflow(7)));
        assert!(ws.give(Kind::Window, wire::window(1).to_vec()).is_err());
    }

    #[test]
    fn a_frame_of_a_bridge_that_ended_is_let_go() {
        let (http, rx) = stream(false);
        drop(rx);
        assert_eq!(http.give(Kind::End, Vec::new()), Ok(Given::Ended));
        assert_eq!(http.give(Kind::Reset, Vec::new()), Ok(Given::Ended));
    }

    #[test]
    fn the_peer_is_the_forwarded_address_or_the_stream() {
        let open = |headers: Vec<(String, String)>| Open {
            method: "GET".into(),
            path: "/".into(),
            headers,
            body: false,
            websocket: None,
        };
        let forwarded = open(vec![("X-Forwarded-For".into(), "192.0.2.4, 10.0.0.1".into())]);
        assert_eq!(peer_of(&forwarded, 3), "192.0.2.4");
        assert_eq!(peer_of(&open(vec![("x-forwarded-for".into(), "nonsense".into())]), 3), "hostc's stream 3");
    }
}
