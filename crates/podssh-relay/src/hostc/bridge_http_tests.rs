//! The bridge of a request, with the test as hostc's server on one side
//! (the frames that it gives and takes) and as the node's side on the other
//! (the pipe's plain HTTP/1.1).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::super::bridge::{self, Given, Stream, PIPE};
use super::super::link::Out;
use super::super::wire::{self, Kind, Open};
use super::super::STREAM_WINDOW;
use super::Body;
use crate::opentunnel::dial::BoxIo;
use crate::pinggy::far::Visitor;

const WAIT: Duration = Duration::from_secs(10);

struct Run {
    stream: Stream,
    out: mpsc::Receiver<Out>,
    node: BoxIo,
}

/// The stream 9 of `open`, started, with the node's end of its pipe.
async fn started(open: Open) -> Run {
    let (outbox, out) = mpsc::channel(1024);
    let (visitors, mut arrived) = mpsc::channel::<Visitor>(4);
    let (done, _done_rx) = mpsc::unbounded_channel();
    let stream = bridge::start(9, open, "abcdefghijkm.hostc.test", outbox, &visitors, done).unwrap();
    let visitor = tokio::time::timeout(WAIT, arrived.recv()).await.unwrap().unwrap();
    assert_eq!(visitor.peer, "hostc's stream 9");
    Run { stream, out, node: visitor.stream }
}

fn post(path: &str) -> Open {
    Open { method: "POST".into(), path: path.into(), headers: vec![], body: true, websocket: None }
}

/// The frames that came within `within`, each of stream 9.
async fn frames(out: &mut mpsc::Receiver<Out>, within: Duration) -> Vec<(Kind, Vec<u8>)> {
    let mut got = Vec::new();
    while let Ok(Some(Out::Frame(bytes))) = tokio::time::timeout(within, out.recv()).await {
        let frame = wire::decode(&bytes).unwrap();
        assert_eq!(frame.stream, 9);
        got.push((frame.kind, frame.payload));
    }
    got
}

fn granted(frames: &[(Kind, Vec<u8>)]) -> usize {
    frames.iter().filter(|(k, _)| *k == Kind::Window).map(|(_, p)| wire::granted(p).unwrap() as usize).sum()
}

/// The head, then everything up to the end of a chunked body.
async fn read_request(node: &mut BoxIo) -> String {
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while !got.ends_with(b"0\r\n\r\n") {
        let n = tokio::time::timeout(WAIT, node.read(&mut chunk)).await.unwrap().unwrap();
        assert!(n > 0, "the pipe ended: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[tokio::test]
async fn a_request_becomes_plain_http_and_its_answer_head_data_and_end() {
    let mut run = started(post("/v1/mint?x=1")).await;
    assert_eq!(run.stream.give(Kind::Data, b"{}".to_vec()), Ok(Given::Taken));
    assert_eq!(run.stream.give(Kind::End, Vec::new()), Ok(Given::Taken));
    let asked = read_request(&mut run.node).await;
    assert!(asked.starts_with("POST /v1/mint?x=1 HTTP/1.1\r\nHost: abcdefghijkm.hostc.test\r\n"), "{asked}");
    assert!(
        asked.contains("Transfer-Encoding: chunked\r\n") && asked.ends_with("\r\n\r\n2\r\n{}\r\n0\r\n\r\n"),
        "{asked}"
    );
    run.node.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await.unwrap();
    let got = frames(&mut run.out, Duration::from_millis(500)).await;
    assert_eq!(granted(&got), 2, "the two bytes that the pipe took");
    let head: wire::Head = serde_json::from_slice(&got.iter().find(|(k, _)| *k == Kind::Head).unwrap().1).unwrap();
    assert_eq!((head.status, head.body), (200, true));
    assert!(head.headers.iter().any(|(n, v)| n == "content-length" && v == "5"));
    assert!(!head.headers.iter().any(|(n, _)| n == "connection"), "a header of one hop");
    let data: Vec<u8> = got.iter().filter(|(k, _)| *k == Kind::Data).flat_map(|(_, p)| p.clone()).collect();
    assert_eq!(data, b"hello");
    assert_eq!(got.last().map(|(k, _)| *k), Some(Kind::End));
}

/// Planted defect (T-742): grant the window when a `DATA` arrives, not once
/// the pipe took its bytes; this test then sees grants for bytes that the
/// node's side never read.
#[tokio::test]
async fn a_window_is_granted_only_for_bytes_that_the_role_took() {
    let mut run = started(post("/upload")).await;
    for _ in 0..4 {
        assert_eq!(run.stream.give(Kind::Data, vec![7; 64 * 1024]), Ok(Given::Taken));
    }
    // The node's side reads nothing: the pipe holds at most its buffer.
    let early = frames(&mut run.out, Duration::from_millis(300)).await;
    assert!(granted(&early) <= PIPE, "granted {} bytes that the role did not take", granted(&early));
    assert!(run.stream.give(Kind::Data, vec![0; 1]).is_err(), "the window is full: one byte more breaks it");
    assert_eq!(run.stream.give(Kind::End, Vec::new()), Ok(Given::Taken));
    let asked = read_request(&mut run.node).await;
    assert!(asked.len() > STREAM_WINDOW);
    let late = frames(&mut run.out, Duration::from_millis(300)).await;
    assert_eq!(granted(&early) + granted(&late), STREAM_WINDOW, "each byte granted back once taken");
}

/// Planted defect (T-742): send `DATA` past the server's grants; this test
/// then sees more than one window of a body that its visitor did not take,
/// held in the node's memory and the server's.
#[tokio::test]
async fn a_visitor_that_does_not_read_holds_the_role_back_at_one_window() {
    let open = Open { method: "GET".into(), path: "/big".into(), headers: vec![], body: false, websocket: None };
    let mut run = started(open).await;
    let mut head = vec![0u8; 1024];
    let n = run.node.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("GET /big HTTP/1.1\r\n"));
    let size = 4 * 1024 * 1024;
    let (mut node_read, mut node_write) = tokio::io::split(run.node);
    let writing = tokio::spawn(async move {
        node_write.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").as_bytes()).await.unwrap();
        node_write.write_all(&vec![1u8; size]).await.unwrap();
        let _ = node_read.read(&mut [0u8; 1]).await;
    });
    let got = frames(&mut run.out, Duration::from_millis(500)).await;
    let sent: usize = got.iter().filter(|(k, _)| *k == Kind::Data).map(|(_, p)| p.len()).sum();
    // The pieces are as the pipe gives them: the last that would pass the
    // window waits, so what went is within one piece of the window.
    let within = STREAM_WINDOW - super::super::MAX_CHUNK < sent && sent <= STREAM_WINDOW;
    assert!(within, "{sent} bytes: one window, no more, while the visitor grants none");
    assert!(!writing.is_finished(), "the node's side is held back, not read into memory");
    assert_eq!(run.stream.give(Kind::Window, wire::window(size as u32).to_vec()), Ok(Given::Taken));
    let rest = frames(&mut run.out, Duration::from_millis(1000)).await;
    let more: usize = rest.iter().filter(|(k, _)| *k == Kind::Data).map(|(_, p)| p.len()).sum();
    assert_eq!(sent + more, size);
    assert_eq!(rest.last().map(|(k, _)| *k), Some(Kind::End));
}

#[tokio::test]
async fn an_answer_s_body_is_read_by_its_length_its_chunks_or_its_end() {
    let read_all = |buf: &'static [u8], chunked: bool, left: Option<u64>| async move {
        let mut body = Body { buf: Vec::new(), chunked, left, ended: false, in_chunk: 0 };
        let mut from = buf;
        let mut got = Vec::new();
        while let Some(piece) = body.next(&mut from, 3).await? {
            assert!(piece.len() <= 3);
            got.extend_from_slice(&piece);
        }
        Ok::<_, String>(got)
    };
    assert_eq!(read_all(b"hello", false, Some(5)).await.unwrap(), b"hello");
    assert_eq!(read_all(b"hello world", false, None).await.unwrap(), b"hello world");
    assert_eq!(read_all(b"5;x=y\r\nhello\r\n1\r\n!\r\n0\r\nTrailer: t\r\n\r\n", true, None).await.unwrap(), b"hello!");
    assert!(read_all(b"hel", false, Some(5)).await.is_err(), "short of its length");
    assert!(read_all(b"5\r\nhelloXX", true, None).await.is_err(), "no CRLF after a chunk");
    assert!(read_all(b"zz\r\n", true, None).await.is_err(), "a bad size");
}
