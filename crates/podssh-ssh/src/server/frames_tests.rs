//! Serve's frames with no SSH (T-303): the pump's sink, the task that
//! sends, and a client's receiver at the other end of a pipe, on the
//! clock of the test.

use tokio::io::{AsyncReadExt, DuplexStream};

use super::*;
use crate::frames::receiver::Receiver;

fn size(cols: u32, rows: u32) -> Size {
    Size { cols, rows, px_width: 0, px_height: 0 }
}

/// A client: what it read of the frames, and the bytes that they took.
struct Near {
    from: DuplexStream,
    receiver: Receiver,
    bytes: usize,
}

impl Near {
    /// Read frames until `done` holds.
    async fn until(&mut self, done: impl Fn(&Receiver) -> bool) {
        let mut buf = vec![0u8; 1 << 16];
        while !done(&self.receiver) {
            // On the paused clock, a frame that never comes fails at once.
            let read = tokio::time::timeout(Duration::from_secs(60), self.from.read(&mut buf)).await;
            let n = read.expect("a frame within the wait").expect("the pipe");
            assert!(n > 0, "the frames ended first");
            self.bytes += n;
            self.receiver.feed(&buf[..n]).expect("frames of this version");
        }
    }

    fn text(&self) -> String {
        self.receiver.state().map(|state| state.screen.contents()).unwrap_or_default()
    }
}

fn started(cols: u32, rows: u32) -> (Arc<Shared>, Sink, Near, DuplexStream, tokio::task::JoinHandle<()>) {
    let shared = Shared::new(size(cols, rows));
    let (out, from) = tokio::io::duplex(1 << 20);
    let (answers, pty) = tokio::io::duplex(1 << 10);
    let task = tokio::spawn(shared.clone().run(out, answers));
    let near = Near { from, receiver: Receiver::default(), bytes: 0 };
    (shared.clone(), shared.sink(), near, pty, task)
}

/// The pty's output shows at the client as frames; a question of the
/// program is answered on the pty; a new size comes as a whole screen of
/// that size; the end of the output sends the last frame, and the task ends.
#[tokio::test(start_paused = true)]
async fn the_pty_output_shows_as_frames_to_its_end() {
    let (shared, mut sink, mut near, mut pty, task) = started(20, 4);
    sink.write_all(b"hello\x1b[6n").await.unwrap();
    near.until(|r| r.newest() >= 1).await;
    assert_eq!(near.text().trim_end(), "hello");
    let mut answer = [0u8; 6];
    pty.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"\x1b[1;6R", "the cursor's place, on the pty");
    shared.acked(near.receiver.take_ack().unwrap());

    shared.resize(size(30, 6));
    sink.write_all(b"\r\nwide").await.unwrap();
    near.until(|r| r.state().is_some_and(|state| state.size() == (6, 30))).await;
    shared.acked(near.receiver.take_ack().unwrap());
    near.until(|r| r.state().is_some_and(|state| state.screen.contents().contains("wide"))).await;

    sink.write_all(b"\r\nbye").await.unwrap();
    drop(sink);
    near.until(Receiver::ended).await;
    assert!(near.text().contains("bye"), "the last frame holds the last output: {:?}", near.text());
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("the task ends with the output").unwrap();
}

/// A flood crosses as a frame or two, not as its bytes: a megabyte of
/// lines that no acknowledgement follows costs the link less than 16 KiB,
/// and the client shows the last lines.
#[tokio::test(start_paused = true)]
async fn a_flood_crosses_as_frames_not_as_its_bytes() {
    let (_shared, mut sink, mut near, _pty, _task) = started(80, 24);
    let mut written = 0usize;
    let mut n = 0u64;
    while written < 1 << 20 {
        n += 1;
        let line = format!("flood line {n} of a program that prints for ever\r\n");
        sink.write_all(line.as_bytes()).await.unwrap();
        written += line.len();
    }
    sink.write_all(b"$ ").await.unwrap();
    let last = format!("flood line {n} ");
    near.until(|r| r.state().is_some_and(|state| state.screen.contents().contains(&last))).await;
    assert!(near.text().trim_end().ends_with("$"), "the prompt after the flood: {:?}", near.text());
    assert!(near.bytes < 16 << 10, "{} bytes crossed for {written} of output", near.bytes);
}
