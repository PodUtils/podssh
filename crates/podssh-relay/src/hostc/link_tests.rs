//! A socket of the tunnel, with the test as hostc's server: its frames go
//! unmasked, as a server's, and the node's come masked. The heartbeat's
//! times are shortened.

use std::time::Duration;

use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch};

use super::super::wire::{self, Kind, Open};
use super::{serve, Beat, Ended, CLOSE_PROTOCOL, CLOSE_SHUTDOWN};
use crate::pinggy::far::Visitor;

const WAIT: Duration = Duration::from_secs(10);

/// The server's end of a socket.
struct Server {
    io: DuplexStream,
    buf: Vec<u8>,
}

impl Server {
    async fn send(&mut self, opcode: u8, payload: Vec<u8>) {
        self.io.write_all(&frame::encode(&Frame { fin: true, opcode, payload }, Role::Server, [0; 4])).await.unwrap();
    }

    async fn frame(&mut self, kind: Kind, stream: u32, payload: &[u8]) {
        self.send(frame::OPCODE_BINARY, wire::encode(kind, stream, payload)).await;
    }

    /// The node's next message, as the server reads one.
    async fn next(&mut self) -> Frame {
        loop {
            if let Some((f, used)) = frame::decode(&self.buf, Role::Client).unwrap() {
                self.buf.drain(..used);
                return f;
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(WAIT, self.io.read(&mut chunk)).await.unwrap().unwrap();
            assert!(n > 0, "the node ended the socket");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// The node's next frame of the protocol, its pings let go.
    async fn protocol_frame(&mut self) -> wire::Frame {
        loop {
            let f = self.next().await;
            if f.opcode == frame::OPCODE_BINARY {
                return wire::decode(&f.payload).unwrap();
            }
        }
    }
}

struct Run {
    server: Server,
    visitors: mpsc::Receiver<Visitor>,
    stop: watch::Sender<bool>,
    ended: tokio::task::JoinHandle<Ended>,
}

fn started(beat: Beat) -> Run {
    let (node, io) = tokio::io::duplex(256 * 1024);
    let (to_node, visitors) = mpsc::channel(8);
    let (stop, stopped) = watch::channel(false);
    let name = "abcdefghijkm.hostc.test".to_string();
    let ended = tokio::spawn(serve(Box::new(node), Vec::new(), name, to_node, beat, stopped));
    Run { server: Server { io, buf: Vec::new() }, visitors, stop, ended }
}

fn long_beat() -> Beat {
    Beat { every: Duration::from_secs(3600), wait: Duration::from_secs(3600) }
}

fn get(path: &str) -> Vec<u8> {
    let open = Open { method: "GET".into(), path: path.into(), headers: vec![], body: false, websocket: None };
    serde_json::to_vec(&open).unwrap()
}

#[tokio::test]
async fn an_open_of_the_server_reaches_the_node_as_a_visitor_and_its_answer_goes_back() {
    let mut run = started(long_beat());
    run.server.frame(Kind::Open, 1, &get("/health")).await;
    let mut visitor = tokio::time::timeout(WAIT, run.visitors.recv()).await.unwrap().unwrap().stream;
    let mut head = vec![0u8; 1024];
    let n = visitor.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("GET /health HTTP/1.1\r\nHost: abcdefghijkm.hostc.test\r\n")
    );
    visitor.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
    let kinds = [Kind::Head, Kind::Data, Kind::End];
    for kind in kinds {
        let f = run.server.protocol_frame().await;
        assert_eq!((f.kind, f.stream), (kind, 1));
    }
    // A frame of a stream that ended is let go; the socket goes on.
    run.server.frame(Kind::Window, 1, &wire::window(5)).await;
    run.server.frame(Kind::Data, 77, b"of nothing").await;
    let _ = run.stop.send(true);
    let close = loop {
        let f = run.server.next().await;
        if f.opcode == frame::OPCODE_CLOSE {
            break f;
        }
    };
    assert_eq!(close.payload[..2], CLOSE_SHUTDOWN.to_be_bytes(), "a stop frees the tunnel at once");
    assert_eq!(tokio::time::timeout(WAIT, run.ended).await.unwrap().unwrap(), Ended::Stopped);
}

#[tokio::test]
async fn a_broken_protocol_closes_the_socket_with_1002() {
    let mut run = started(long_beat());
    run.server.frame(Kind::Open, 1, &get("/")).await;
    run.server.frame(Kind::Open, 1, &get("/")).await;
    let close = loop {
        let f = run.server.next().await;
        if f.opcode == frame::OPCODE_CLOSE {
            break f;
        }
    };
    assert_eq!(close.payload[..2], CLOSE_PROTOCOL.to_be_bytes());
    let ended = tokio::time::timeout(WAIT, run.ended).await.unwrap().unwrap();
    assert!(matches!(ended, Ended::Protocol(why) if why.contains("open stream 1")));
}

#[tokio::test]
async fn the_heartbeat_pings_and_a_socket_that_brings_nothing_after_it_is_dead() {
    let beat = Beat { every: Duration::from_millis(100), wait: Duration::from_millis(200) };
    let mut run = started(beat);
    let ping = run.server.next().await;
    assert_eq!((ping.opcode, ping.payload.as_slice()), (frame::OPCODE_TEXT, &b"hostc:ping"[..]));
    // Any message proves the socket alive, the pong or another.
    run.server.send(frame::OPCODE_TEXT, b"hostc:pong".to_vec()).await;
    let ended = tokio::time::timeout(WAIT, run.ended).await.unwrap().unwrap();
    assert!(matches!(ended, Ended::Dropped(why) if why.contains("of a ping")), "silent after a later ping");
}

#[tokio::test]
async fn the_server_s_close_is_a_drop_that_names_a_replaced_socket() {
    let mut run = started(long_beat());
    run.server.send(frame::OPCODE_CLOSE, wire::close(4001, "replaced")).await;
    let ended = tokio::time::timeout(WAIT, run.ended).await.unwrap().unwrap();
    assert!(matches!(ended, Ended::Dropped(why) if why.contains("4001") && why.contains("replaced")));
}
