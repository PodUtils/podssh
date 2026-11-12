//! The bridge of a visitor's WebSocket, with the test as hostc's server on
//! one side and as the node's WebSocket server on the pipe: the node's
//! answer is the 101 that podssh-ws's server writes, so the handshake is
//! the one that the relay role and the node's links answer.

use std::time::Duration;

use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::http::request::read_request;
use podssh_ws::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::super::bridge::{self, Given};
use super::super::link::Out;
use super::super::wire::{self, Head, Kind, Open};
use super::super::MAX_MESSAGE;
use super::pieces;
use crate::pinggy::far::Visitor;

const WAIT: Duration = Duration::from_secs(10);

async fn next(out: &mut mpsc::Receiver<Out>) -> (Kind, Vec<u8>) {
    match tokio::time::timeout(WAIT, out.recv()).await.unwrap().unwrap() {
        Out::Frame(bytes) => {
            let f = wire::decode(&bytes).unwrap();
            assert_eq!(f.stream, 3);
            (f.kind, f.payload)
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_visitor_s_websocket_is_upgraded_on_the_pipe_and_its_messages_pass_both_ways() {
    let (outbox, mut out) = mpsc::channel(64);
    let (visitors, mut arrived) = mpsc::channel::<Visitor>(4);
    let (done, _done_rx) = mpsc::unbounded_channel();
    let headers = vec![("Host".into(), "abcdefghijkm.hostc.test".into()), ("Origin".into(), "https://x.test".into())];
    let open = Open { method: "GET".into(), path: "/".into(), headers, body: false, websocket: Some(vec![]) };
    let stream = bridge::start(3, open, "abcdefghijkm.hostc.test", outbox, &visitors, done).unwrap();
    let mut node = tokio::time::timeout(WAIT, arrived.recv()).await.unwrap().unwrap().stream;
    // The node's side: the upgrade, checked as the role's server checks it.
    let (head, pending) = read_request(&mut node, Vec::new()).await.unwrap();
    assert!(pending.is_empty());
    assert_eq!((head.method.as_str(), head.target.as_str()), ("GET", "/"));
    assert_eq!(head.header("host"), Some("abcdefghijkm.hostc.test"));
    let key = server::check_upgrade(&head).expect("an upgrade that podssh's server takes");
    node.write_all(&server::switching(&key)).await.unwrap();
    let (kind, payload) = next(&mut out).await;
    let switched: Head = serde_json::from_slice(&payload).unwrap();
    assert_eq!((kind, switched.status, switched.protocol), (Kind::Head, 101, None));
    assert!(!switched.headers.iter().any(|(n, _)| n == "sec-websocket-accept"), "made by the server itself");
    // The visitor's message reaches the node masked, as a client's.
    assert_eq!(stream.give(Kind::Data, b"to the node".to_vec()), Ok(Given::Taken));
    let mut buf = Vec::new();
    let got = loop {
        if let Some((f, _)) = frame::decode(&buf, Role::Client).unwrap() {
            break f;
        }
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(WAIT, node.read(&mut chunk)).await.unwrap().unwrap();
        buf.extend_from_slice(&chunk[..n]);
    };
    assert_eq!((got.opcode, got.payload.as_slice()), (frame::OPCODE_BINARY, &b"to the node"[..]));
    // The node's message reaches the visitor as DATA; its close as END.
    let message = Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"to the visitor".to_vec() };
    node.write_all(&frame::encode(&message, Role::Server, [0; 4])).await.unwrap();
    assert_eq!(next(&mut out).await, (Kind::Data, b"to the visitor".to_vec()));
    let close = Frame { fin: true, opcode: frame::OPCODE_CLOSE, payload: wire::close(1000, "bye") };
    node.write_all(&frame::encode(&close, Role::Server, [0; 4])).await.unwrap();
    assert_eq!(next(&mut out).await, (Kind::End, wire::close(1000, "bye")));
}

#[tokio::test]
async fn a_refused_upgrade_passes_to_the_visitor_with_no_body() {
    let (outbox, mut out) = mpsc::channel(64);
    let (visitors, mut arrived) = mpsc::channel::<Visitor>(4);
    let (done, _done_rx) = mpsc::unbounded_channel();
    let open = Open { method: "GET".into(), path: "/x".into(), headers: vec![], body: false, websocket: Some(vec![]) };
    let _stream = bridge::start(3, open, "n.hostc.test", outbox, &visitors, done).unwrap();
    let mut node = tokio::time::timeout(WAIT, arrived.recv()).await.unwrap().unwrap().stream;
    let _ = read_request(&mut node, Vec::new()).await.unwrap();
    node.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found").await.unwrap();
    let (kind, payload) = next(&mut out).await;
    let refused: Head = serde_json::from_slice(&payload).unwrap();
    assert_eq!((kind, refused.status, refused.body), (Kind::Head, 404, false));
    assert!(!refused.headers.iter().any(|(n, _)| n == "content-length"));
}

#[test]
fn a_binary_message_longer_than_hostc_passes_goes_in_parts() {
    let long = vec![0u8; MAX_MESSAGE * 2 + 1];
    let parts = pieces(&long);
    assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [MAX_MESSAGE, MAX_MESSAGE, 1]);
    assert_eq!(pieces(&[]).len(), 1, "an empty message stays one");
}
