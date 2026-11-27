//! Serve's frames with no SSH (T-303): the pump's sink, the task that
//! sends, and a client's receiver at the other end of a pipe, on the
//! clock of the test.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use super::epoch::Sink;
use super::*;
use crate::frames::receiver::Receiver;
use crate::frames::sender::COLLECT;

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
    let shared = Shared::new(size(cols, rows), Version::Two);
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

/// The frames are of the version that the client asked: version 2 carries
/// the lines that left the top of the screen, version 1 none. One table:
/// the version, its first byte, whether lines come.
#[tokio::test(start_paused = true)]
async fn the_frames_are_of_the_version_asked() {
    for (version, first, lined) in [(Version::Two, 2u8, true), (Version::One, 1, false)] {
        let shared = Shared::new(size(20, 4), version);
        let (out, mut from) = tokio::io::duplex(1 << 20);
        let (answers, _pty) = tokio::io::duplex(1 << 10);
        let task = tokio::spawn(shared.clone().run(out, answers));
        let mut sink = shared.sink();
        for n in 1..=10 {
            sink.write_all(format!("line {n}\r\n").as_bytes()).await.unwrap();
        }
        drop(sink);
        let mut bytes = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(60), from.read_to_end(&mut bytes)).await;
        read.expect("the frames end with the output").expect("the pipe");
        task.await.unwrap();
        assert_eq!(bytes.first(), Some(&first), "{version:?}");
        let frames = crate::frames::wire::Decoder::default().feed(&bytes).expect("frames");
        let lines: Vec<String> =
            frames.iter().flat_map(|f| f.lines.iter().map(|l| String::from_utf8_lossy(l).into_owned())).collect();
        assert_eq!(!lines.is_empty(), lined, "{version:?}: {lines:?}");
        // Lines 1 to 7 left a screen of 4 rows; the newest 4 of them go.
        if lined {
            assert_eq!(lines[lines.len() - 4..], ["line 4", "line 5", "line 6", "line 7"], "{lines:?}");
            assert!(frames.iter().all(|f| f.head.total == 7), "the count of each frame");
        }
    }
}

/// The handler runs on the SSH session's task, which also takes the
/// client's Ctrl-C to the pty: an acknowledgement or a new size never
/// waits for the model, which the pump holds nearly all the time under a
/// flood. Here a thread holds the model as the pump does, and another
/// says what a client said.
#[test]
fn the_handler_never_waits_for_the_model() {
    let shared = Shared::new(size(20, 4), Version::Two);
    let pump = shared.lock();
    let handler = shared.clone();
    let (said, heard) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        handler.acked(Ack { number: 0, lost: false });
        handler.resize(size(30, 6));
        let _ = said.send(());
    });
    let waited = heard.recv_timeout(std::time::Duration::from_secs(5));
    drop(pump);
    thread.join().unwrap();
    assert!(waited.is_ok(), "the handler waited for the model's lock");
    // What it said reaches the model at the pump's next write.
    let mut sink = shared.sink();
    let mut context = Context::from_waker(std::task::Waker::noop());
    let wrote = Pin::new(&mut sink).poll_write(&mut context, b"x");
    assert!(matches!(wrote, Poll::Ready(Ok(1))));
    assert_eq!(shared.lock().model.state().size(), (6, 30), "the new size, before the output");
}

/// A flood that only scrolls (`yes`), with a client that acknowledges each
/// frame a round trip after it came: the prompt after Ctrl-C shows within
/// the collection of its change, never behind frames of lines.
#[tokio::test(start_paused = true)]
async fn under_a_flood_that_only_scrolls_the_prompt_shows_at_once() {
    let trip = Duration::from_millis(300);
    let (shared, mut sink, near, _pty, _task) = started(20, 4);
    let Near { mut from, mut receiver, .. } = near;
    let (shown, mut prompt) = tokio::sync::watch::channel(None::<Instant>);
    let acking = shared.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(n @ 1..) = from.read(&mut buf).await {
            receiver.feed(&buf[..n]).expect("frames of this version");
            let text = receiver.state().map(|state| state.screen.contents()).unwrap_or_default();
            if text.trim_end().ends_with('$') {
                let _ = shown.send(Some(Instant::now()));
            }
            if let Some(ack) = receiver.take_ack() {
                let acking = acking.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(trip).await;
                    acking.acked(ack);
                });
            }
        }
    });
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        sink.write_all("y\r\n".repeat(30).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let ctrl_c = Instant::now();
    sink.write_all(b"^C\r\n$ ").await.unwrap();
    let seen = tokio::time::timeout(Duration::from_secs(30), prompt.wait_for(Option::is_some)).await;
    let at = (*seen.expect("the prompt shows").expect("the client reads")).expect("a time");
    let after = at - ctrl_c;
    assert!(after <= COLLECT, "the prompt showed {after:?} after its change, over the collection");
}

/// A kept shell's model across its channels (T-159): a released model is
/// fed with no frame made and its epoch's task ends; the next epoch's first
/// frame is the whole screen, numbered after the last epoch's, and an
/// acknowledgement of an older epoch's frame goes nowhere.
#[tokio::test(start_paused = true)]
async fn each_epoch_starts_with_the_whole_screen_and_ends_the_last() {
    let shared = Shared::new(size(20, 4), Version::One);
    let mut sink = shared.sink();
    let near = |from| Near { from, receiver: Receiver::default(), bytes: 0 };
    let (out, from) = tokio::io::duplex(1 << 16);
    let (answers, _pty) = tokio::io::duplex(1 << 10);
    let task = tokio::spawn(shared.clone().run_epoch(0, out, answers, None::<tokio::io::Sink>));
    let mut first = near(from);
    sink.write_all(b"one").await.unwrap();
    first.until(|r| r.newest() >= 1).await;
    assert_eq!(first.receiver.newest(), 1);

    shared.release();
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("a released epoch's task ends").unwrap();
    sink.write_all(b" two").await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(shared.lock().views.is_empty(), "no view, so no frame, with no channel");

    let epoch = shared.restart(Version::One);
    let (out, from) = tokio::io::duplex(1 << 16);
    let (answers, _pty) = tokio::io::duplex(1 << 10);
    let task = tokio::spawn(shared.clone().run_epoch(epoch, out, answers, None::<tokio::io::Sink>));
    let mut second = near(from);
    second.until(|r| r.state().is_some_and(|state| state.screen.contents().contains("one two"))).await;
    assert!(second.receiver.newest() > 1, "the numbers go on from the last epoch's");
    shared.acked(Ack { number: 1, lost: true });
    let acks = shared.lane(epoch).map(|lane| unpoisoned(&lane.acks).len());
    assert_eq!(acks, Some(0), "an older channel's acknowledgement goes nowhere");
    drop(sink);
    second.until(Receiver::ended).await;
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("the task ends with the output").unwrap();
}

/// One step of the order of local echo's reports in the frames' queue.
#[derive(Debug, Clone, Copy)]
enum Act {
    /// The pump writes the pty's output.
    Out(&'static [u8]),
    /// The pump's reporter tells a report, here one byte.
    Report(u8),
    /// The clock moves on, and the frame that is due is made.
    Wait(u64),
}

/// The queue, taken: `F` for a frame, the byte for a report.
fn queued(shared: &Shared) -> String {
    let lane = shared.lane(FIRST_VIEW).expect("the first view");
    let made = std::mem::take(&mut *unpoisoned(&lane.queue));
    made.into_iter()
        .map(|out| match out {
            Out::Frame(_) => "F".to_string(),
            Out::Report(bytes) => bytes.iter().map(u8::to_string).collect(),
        })
        .collect()
}

/// Local echo's reports go in the frames' queue (T-160 with T-303), so the
/// client judges each guess on a screen that holds its echo: a report made
/// while a change waits for its frame goes right after that frame; one
/// made with no change waiting goes at once; a change that leaves the
/// client's screen as it is lets the waiting reports go with no frame. One
/// table: each run's steps, and the queue after each.
#[tokio::test(start_paused = true)]
async fn a_report_goes_after_the_frame_of_the_output_before_it() {
    #[rustfmt::skip]
    let runs: &[(&str, &[(Act, &str)])] = &[
        ("no change waits", &[(Act::Report(1), "1")]),
        ("a change waits for its frame", &[
            (Act::Out(b"a"), ""), (Act::Report(1), ""), (Act::Report(2), ""), (Act::Wait(10), "F12"),
            (Act::Report(3), "3"),
        ]),
        ("a change that the client's screen already shows", &[
            (Act::Out(b"a"), ""), (Act::Wait(10), "F"),
            (Act::Out(b"\x1b[1C\x1b[1D"), ""), (Act::Report(1), ""), (Act::Wait(300), "1"),
        ]),
    ];
    for (name, steps) in runs {
        let shared = Shared::new(size(20, 4), Version::One);
        let mut sink = shared.sink();
        let mut reports = shared.reports();
        for (i, &(act, after)) in steps.iter().enumerate() {
            match act {
                Act::Out(bytes) => sink.write_all(bytes).await.unwrap(),
                Act::Report(byte) => reports.write_all(&[byte]).await.unwrap(),
                Act::Wait(ms) => {
                    tokio::time::advance(Duration::from_millis(ms)).await;
                    let mut guard = shared.lock();
                    shared.make(&mut guard, Instant::now());
                }
            }
            assert_eq!(queued(&shared), after, "{name}, step {i}: {act:?}");
        }
    }
}

/// A writer that notes each write's tag, in the order of the writes.
struct Tagged(Arc<Mutex<Vec<char>>>, char);

impl AsyncWrite for Tagged {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        unpoisoned(&self.0).push(self.1);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The task that sends writes each report on the reports' own writer,
/// after the frame it waited for; at the end of the output the last frame
/// takes the reports that wait.
#[tokio::test(start_paused = true)]
async fn the_last_frame_takes_the_reports_that_wait() {
    let shared = Shared::new(size(20, 4), Version::One);
    let order = Arc::new(Mutex::new(Vec::new()));
    let (frames, told) = (Tagged(order.clone(), 'F'), Tagged(order.clone(), 'R'));
    let (answers, _pty) = tokio::io::duplex(1 << 10);
    let task = tokio::spawn(shared.clone().run_told(frames, answers, Some(told)));
    let mut sink = shared.sink();
    let mut reports = shared.reports();
    sink.write_all(b"$ ls").await.unwrap();
    reports.write_all(&[1]).await.unwrap();
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("the task ends with the output").unwrap();
    assert_eq!(*unpoisoned(&order), ['F', 'R'], "the last frame, then the report that waited for it");
}
