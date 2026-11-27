//! The views of one model (T-303 with T-837), with no SSH: each view has
//! its own sender, base and acknowledgements; one view at most answers the
//! program's questions; a view that leaves ends its task alone; and a
//! report made beside the pump waits for the frame of the output before
//! it, as the pump's own does. On the clock of the test.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::frames::receiver::Receiver;
use crate::frames::wire::Decoder;

fn size(cols: u32, rows: u32) -> Size {
    Size { cols, rows, px_width: 0, px_height: 0 }
}

/// A client of one view: the bytes of its frames, and what they drew.
struct Client {
    from: DuplexStream,
    receiver: Receiver,
    bytes: Vec<u8>,
}

impl Client {
    fn new(from: DuplexStream) -> Client {
        Client { from, receiver: Receiver::default(), bytes: Vec::new() }
    }

    fn text(&self) -> String {
        self.receiver.state().map(|state| state.screen.contents()).unwrap_or_default()
    }

    /// Read frames until the screen that they draw holds `needle`.
    async fn until(&mut self, needle: &str) {
        let mut buf = vec![0u8; 1 << 16];
        while !self.text().contains(needle) {
            // On the paused clock, a frame that never comes fails at once.
            let read = tokio::time::timeout(Duration::from_secs(60), self.from.read(&mut buf)).await;
            let n = read.expect("a frame within the wait").expect("the pipe");
            assert!(n > 0, "the frames ended before {needle:?}: {:?}", self.text());
            self.bytes.extend_from_slice(&buf[..n]);
            self.receiver.feed(&buf[..n]).expect("frames of this version");
        }
    }

    /// Read the frames to the end of the pipe: the view's task ended.
    async fn drain_to_end(&mut self) {
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(60), self.from.read_to_end(&mut rest)).await;
        read.expect("the view's task ends").expect("the pipe");
        self.receiver.feed(&rest).expect("frames of this version");
        self.bytes.extend_from_slice(&rest);
    }

    /// The header of each frame that came.
    fn heads(&self) -> Vec<Head> {
        Decoder::default().feed(&self.bytes).expect("frames").into_iter().map(|frame| frame.head).collect()
    }
}

/// A task for `view`, with its client and the pty where its answers go.
fn watch(shared: &Arc<Shared>, view: u64) -> (Client, DuplexStream, tokio::task::JoinHandle<()>) {
    let (out, from) = tokio::io::duplex(1 << 20);
    let (answers, pty) = tokio::io::duplex(1 << 10);
    let task = tokio::spawn(shared.clone().run_epoch(view, out, answers, None::<tokio::io::Sink>));
    (Client::new(from), pty, task)
}

/// Two views of one model, as two seats of a shared shell: the one whose
/// client acknowledges gets differences from its base, the one whose client
/// never does gets whole screens; both draw each step, a view that joins
/// late starts from the whole screen so far, and the end sends each its
/// last frame.
#[tokio::test(start_paused = true)]
async fn each_view_has_its_own_base_and_acknowledgements() {
    let shared = Shared::bare(size(20, 4), Version::One);
    shared.fed(b"before\r\n");
    let (keen, quiet) = (shared.join(Version::One), shared.join(Version::One));
    let (mut acking, _pty, first) = watch(&shared, keen);
    let (mut silent, _pty2, second) = watch(&shared, quiet);
    acking.until("before").await;
    silent.until("before").await;
    for n in 1..=5 {
        let step = format!("step {n}");
        shared.fed(format!("{step}\r\n").as_bytes());
        acking.until(&step).await;
        if let Some(ack) = acking.receiver.take_ack() {
            shared.acked_by(keen, ack);
        }
        silent.until(&step).await;
    }
    shared.end();
    acking.drain_to_end().await;
    silent.drain_to_end().await;
    for task in [first, second] {
        tokio::time::timeout(Duration::from_secs(5), task).await.expect("each task ends").unwrap();
    }
    let (keen_heads, quiet_heads) = (acking.heads(), silent.heads());
    assert!(keen_heads.first().is_some_and(|head| head.full), "a view's first frame is the whole screen");
    assert!(keen_heads.iter().any(|head| head.base != 0), "differences from the base acknowledged: {keen_heads:?}");
    assert!(quiet_heads.iter().all(|head| head.base == 0), "no base with no acknowledgement: {quiet_heads:?}");
    for (client, heads) in [(&acking, &keen_heads), (&silent, &quiet_heads)] {
        assert!(heads.last().is_some_and(|head| head.last), "each view's last frame");
        assert!(client.text().contains("step 5"), "{:?}", client.text());
    }
}

/// Which view writes the model's answers to the pty: one table, each run's
/// views (whether a pty's own, opened by `new`), the views that leave
/// before the question, and whether each view's pty got the answer.
#[tokio::test(start_paused = true)]
async fn one_view_at_most_answers_the_program() {
    type Case = (&'static str, bool, usize, &'static [usize], &'static [bool]);
    #[rustfmt::skip]
    let runs: &[Case] = &[
        ("a pty's own view answers, a seat's beside it does not", true, 1, &[], &[true, false]),
        ("a shared shell's seats alone: nobody answers", false, 2, &[], &[false, false]),
        ("the view that answered left: no other takes it up", true, 1, &[0], &[false, false]),
    ];
    for &(name, own, joined, leaving, answered) in runs {
        let shared = if own { Shared::new(size(20, 4), Version::One) } else { Shared::bare(size(20, 4), Version::One) };
        let mut views: Vec<u64> = if own { vec![FIRST_VIEW] } else { Vec::new() };
        views.extend((0..joined).map(|_| shared.join(Version::One)));
        let mut watched: Vec<_> = views.iter().map(|&view| watch(&shared, view)).collect();
        for &at in leaving {
            shared.leave(views[at]);
        }
        shared.fed(b"\x1b[6n");
        for (at, (_, pty, _)) in watched.iter_mut().enumerate() {
            let mut answer = [0u8; 6];
            // A task that ended closes its pty's pipe: no answer either.
            let read = tokio::time::timeout(Duration::from_secs(1), pty.read_exact(&mut answer)).await;
            assert_eq!(matches!(read, Ok(Ok(_))), answered[at], "{name}: view {at}");
            if answered[at] {
                assert_eq!(&answer, b"\x1b[1;1R", "{name}: the cursor's place");
            }
        }
    }
}

/// A view that leaves ends its task with no last frame, and the pump drops
/// it at its next write; the other views go on to the end.
#[tokio::test(start_paused = true)]
async fn a_view_that_leaves_ends_alone() {
    let shared = Shared::bare(size(20, 4), Version::One);
    let (stays, goes) = (shared.join(Version::One), shared.join(Version::One));
    let (mut staying, _pty, kept) = watch(&shared, stays);
    let (mut going, _pty2, left) = watch(&shared, goes);
    shared.fed(b"both");
    staying.until("both").await;
    going.until("both").await;
    shared.leave(goes);
    tokio::time::timeout(Duration::from_secs(5), left).await.expect("its task ends").unwrap();
    going.drain_to_end().await;
    assert!(!going.receiver.ended(), "a view that left gets no last frame");
    shared.fed(b" one");
    assert_eq!(shared.lock().views.keys().copied().collect::<Vec<_>>(), [stays], "the pump dropped it");
    staying.until("both one").await;
    shared.leave(goes);
    shared.end();
    staying.drain_to_end().await;
    assert!(staying.receiver.ended(), "the view that stays gets its last frame");
    tokio::time::timeout(Duration::from_secs(5), kept).await.expect("its task ends").unwrap();
}

/// One step of a report of local echo made beside the pump.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// The pump writes the pty's output.
    Out(&'static [u8]),
    /// A seat's task tells a report, here one byte, into the view's inbox.
    Report(u8),
    /// The clock moves on, and the pump looks: it places the reports and
    /// makes the frame that is due.
    Look(u64),
}

/// A report made beside the pump (a seat's at a shared shell, T-896) waits
/// in its view's inbox for the pump's next look, which places it as the
/// pump's own: after the frame of a change that waits, else at once. One
/// table: each run's steps, and the queue after each (`F` a frame).
#[tokio::test(start_paused = true)]
async fn a_report_beside_the_pump_waits_for_the_frame_before_it() {
    #[rustfmt::skip]
    let runs: &[(&str, &[(Step, &str)])] = &[
        ("no change waits", &[(Step::Report(1), ""), (Step::Look(0), "1")]),
        ("a change waits for its frame", &[
            (Step::Out(b"a"), ""), (Step::Report(1), ""), (Step::Look(0), ""), (Step::Look(10), "F1"),
            (Step::Report(2), ""), (Step::Look(0), "2"),
        ]),
    ];
    for (name, steps) in runs {
        let shared = Shared::new(size(20, 4), Version::One);
        let mut aside = shared.aside(FIRST_VIEW);
        for (i, &(step, after)) in steps.iter().enumerate() {
            match step {
                Step::Out(bytes) => shared.fed(bytes),
                Step::Report(byte) => aside.write_all(&[byte]).await.unwrap(),
                Step::Look(ms) => {
                    tokio::time::advance(Duration::from_millis(ms)).await;
                    let now = Instant::now();
                    let mut guard = shared.lock();
                    shared.heard(&mut guard, now);
                    shared.make(&mut guard, now);
                }
            }
            let lane = shared.lane(FIRST_VIEW).expect("the first view");
            let queue = std::mem::take(&mut *unpoisoned(&lane.queue));
            let queued: String = queue
                .into_iter()
                .map(|out| match out {
                    Out::Frame(_) => "F".to_string(),
                    Out::Report(bytes) => bytes.iter().map(u8::to_string).collect(),
                })
                .collect();
            assert_eq!(queued, after, "{name}, step {i}: {step:?}");
        }
    }
}
