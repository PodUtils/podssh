//! The rule of the lines of `--frames-scroll` as a property (T-1056): at
//! each draw, the lines that the client's scrollback got and the lines that
//! it said skipped come to the count of the state that it drew, and each
//! line that it got is the far end's line of that place. With it, no line
//! leaves the far end's screen without being shown or counted.
//!
//! The far end and the client run on a clock of the test, through a link
//! with a delay each way, at the sender's own pace: no frame is forced due,
//! so frames of lines alone, a full window, late acknowledgements and
//! frames from one base whose lines overlap all come as they come in a
//! session. One table of schedules, each a way in which a frame's lines can
//! start after a gap, overlap another's, come late, or not come.
//!
//! The oracle is a second terminal of the far end's size that reads the
//! pty's bytes and keeps each row that leaves its top: the far end's count
//! must be its count, and its rows the lines.

use std::collections::VecDeque;
use std::num::NonZeroU16;
use std::time::Duration;

use tokio::time::Instant;

use crate::frames::receiver::Receiver;
use crate::frames::screen::Model;
use crate::frames::sender::Sender;
use crate::frames::wire::{encode, Ack, Version};

const ROWS: u16 = 6;
const COLS: u16 = 40;
/// One tick of the clock of the test.
const TICK: Duration = Duration::from_millis(5);
/// The most ticks of a run after its last write: a bound on each run.
const DRAIN: u32 = 4000;
/// The ticks of one batch of a road that reorders: two frames or more at
/// the shortest pace.
const BATCH: u32 = 12;

/// Each row that leaves the top of a primary screen, as its plain text.
#[derive(Default)]
struct Rows(Vec<String>);

impl vt100::Callbacks for Rows {
    fn on_scroll(&mut self, row: vt100::capture::RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        let mut text = String::new();
        let _ = row.write_formatted_basic(&mut text, &mut vt100::capture::BasicFormattedCaptureState::new());
        let plain: String = vt100::capture::basic_formatted_to_plain(&text).collect();
        self.0.push(plain.trim_end().to_string());
    }
}

fn terminal() -> vt100::Parser<Rows> {
    let dim = |n| NonZeroU16::new(n).unwrap();
    vt100::Parser::new_with_callbacks(dim(ROWS), dim(COLS), 0, Rows::default())
}

/// What the pty writes at each write of a schedule.
#[derive(Clone, Copy, Debug)]
enum Output {
    /// Numbered lines.
    Numbered(u64),
    /// Rows that read alike: once the screen is full it looks the same
    /// after each write (a flood of `yes`), so lines go in frames alone.
    Alike(u64),
    /// The screen cleared and the cursor home, then numbered lines: fewer
    /// rows leave than the write has line feeds.
    Cleared(u64),
    /// Numbered lines, then the cursor up three rows and three line feeds
    /// that move no row: the newest rows left before the write's last line
    /// feeds, so the far end keeps fewer than a screen of them.
    UpThenFeeds(u64),
}

/// `count` numbered lines, after the `printed` before them.
fn numbered(out: &mut String, printed: &mut u64, count: u64) {
    for _ in 0..count {
        *printed += 1;
        out.push_str(&format!("line {printed}\r\n"));
    }
}

/// The bytes of one write of `output`.
fn bytes(output: Output, printed: &mut u64) -> Vec<u8> {
    let mut out = String::new();
    match output {
        Output::Numbered(count) => numbered(&mut out, printed, count),
        Output::Alike(count) => (0..count).for_each(|_| out.push_str("y\r\n")),
        Output::Cleared(count) => {
            out.push_str("\x1b[H\x1b[2J");
            numbered(&mut out, printed, count);
        }
        Output::UpThenFeeds(count) => {
            numbered(&mut out, printed, count);
            out.push_str("\x1b[3A\n\n\n");
        }
    }
    out.into_bytes()
}

/// One schedule of the table. Times are in ticks.
struct Schedule {
    what: &'static str,
    output: Output,
    /// The writes, one each `every` ticks.
    writes: u32,
    every: u32,
    /// The link's delay each way.
    delay: u32,
    /// How long each acknowledgement waits before it leaves; `None`: none
    /// leaves, and the window stays full.
    ack_wait: Option<u32>,
    /// The road loses each frame whose count is a multiple of it (a road
    /// of T-304); 0 for none.
    lose: u64,
    /// The frames arrive in batches of [`BATCH`] ticks, each batch read
    /// newest first, each frame alone: a road that reorders, where the
    /// older ones are passed over.
    reorder: bool,
    /// After this write, the client says that it holds no base: the next
    /// frame is the whole screen, and carries the lines after no base.
    lost_at: Option<u32>,
}

fn schedule(what: &'static str, output: Output, writes: u32, every: u32, delay: u32) -> Schedule {
    Schedule { what, output, writes, every, delay, ack_wait: Some(0), lose: 0, reorder: false, lost_at: None }
}

impl Schedule {
    fn acks(self, ack_wait: Option<u32>) -> Schedule {
        Schedule { ack_wait, ..self }
    }

    fn losing(self, lose: u64) -> Schedule {
        Schedule { lose, ..self }
    }

    fn reordered(self) -> Schedule {
        Schedule { reorder: true, ..self }
    }

    fn lost_at(self, write: u32) -> Schedule {
        Schedule { lost_at: Some(write), ..self }
    }
}

/// What a link carries, in order: each item with the tick at which it
/// arrives. A later item never arrives before an earlier one.
fn carry<T>(queue: &mut VecDeque<(u32, T)>, at: u32, item: T) {
    let at = queue.back().map_or(at, |(last, _)| at.max(*last));
    queue.push_back((at, item));
}

/// The items of `queue` that arrived by the tick `now`.
fn arrived<T>(queue: &mut VecDeque<(u32, T)>, now: u32) -> Vec<T> {
    let mut out = Vec::new();
    while queue.front().is_some_and(|(at, _)| *at <= now) {
        out.extend(queue.pop_front().map(|(_, item)| item));
    }
    out
}

/// What the client's scrollback says against the far end's `lines`: each
/// row after the blank ones that the first draw moved up is the line of
/// its place, or a count of lines said skipped. The place reached, the
/// lines carried and the lines said.
fn walk(kept: &[String], lines: &[String], what: &str) -> (u64, u64, u64) {
    let (mut place, mut carried, mut said) = (0u64, 0u64, 0u64);
    for row in kept.iter().skip(usize::from(ROWS)) {
        let count = row.strip_prefix("[podssh: ").and_then(|rest| rest.split(' ').next()?.parse::<u64>().ok());
        if let Some(count) = count {
            (place, said) = (place + count, said + count);
            continue;
        }
        let want = usize::try_from(place).ok().and_then(|at| lines.get(at));
        assert_eq!(Some(row), want, "{what}: the scrollback's line {} is not the far end's", place + 1);
        (place, carried) = (place + 1, carried + 1);
    }
    (place, carried, said)
}

/// Run `s` to its last frame, holding the rule at each draw. The lines
/// carried and the lines said skipped.
fn run(s: &Schedule) -> (u64, u64) {
    let what = s.what;
    let start = Instant::now();
    let mut now = start;
    let (mut model, mut truth, mut sender) = (Model::new(ROWS, COLS, false), terminal(), Sender::default());
    let (mut near, mut term) = (Receiver::default(), terminal());
    let mut frames: VecDeque<(u32, Vec<u8>)> = VecDeque::new();
    let mut acks: VecDeque<(u32, Ack)> = VecDeque::new();
    let (mut printed, mut made, mut written) = (0u64, 0u64, 0u32);
    let end = s.writes * s.every + DRAIN;
    for tick in 1..=end {
        now = start + TICK * tick;
        if written < s.writes && tick % s.every == 0 {
            let out = bytes(s.output, &mut printed);
            model.feed(&out);
            truth.process(&out);
            assert_eq!(model.state().total, truth.callbacks().0.len() as u64, "{what}: the far end's count");
            sender.changed(now);
            written += 1;
            if s.lost_at == Some(written) {
                carry(&mut acks, tick + s.delay, Ack { number: 0, lost: true });
            }
        }
        for ack in arrived(&mut acks, tick) {
            sender.acked(ack, now);
        }
        if sender.due().is_some_and(|due| due <= now) {
            if let Some((head, body)) = sender.frame(&model.state(), false, now) {
                made += 1;
                let frame = encode(Version::Two, head, &model.lines_after(sender.since()), &body);
                // A road that reorders gives its frames in batches.
                let at = if s.reorder { (tick + s.delay).next_multiple_of(BATCH) } else { tick + s.delay };
                if s.lose == 0 || made % s.lose != 0 {
                    carry(&mut frames, at, frame);
                }
            }
        }
        let mut reads = arrived(&mut frames, tick);
        if s.reorder {
            reads.reverse();
        } else if !reads.is_empty() {
            reads = vec![reads.concat()];
        }
        for read in reads {
            let drawn = near.feed(&read).expect("frames of version 2");
            if !drawn.is_empty() {
                term.process(&drawn);
                let (place, _, _) = walk(&term.callbacks().0, &truth.callbacks().0, what);
                let total = near.state().map_or(0, |state| state.total);
                assert_eq!(place, total, "{what}: lines got and said skipped against the count drawn, at tick {tick}");
            }
            if let (Some(ack), Some(wait)) = (near.take_ack(), s.ack_wait) {
                carry(&mut acks, tick + s.delay + wait, ack);
            }
        }
        if written == s.writes && frames.is_empty() && acks.is_empty() && sender.due().is_none() {
            break;
        }
    }
    // The output ended: the last frame, whole, after whatever is on its way.
    let (head, body) = sender.last(&model.state(), false, now);
    let mut read: Vec<u8> = frames.into_iter().flat_map(|(_, frame)| frame).collect();
    read.extend_from_slice(&encode(Version::Two, head, &model.lines_after(sender.since()), &body));
    term.process(&near.feed(&read).expect("frames of version 2"));
    assert!(near.ended(), "{what}: the last frame came");
    let state = model.state();
    assert_eq!(term.screen().contents(), state.screen.contents(), "{what}: the screen");
    let (place, carried, said) = walk(&term.callbacks().0, &truth.callbacks().0, what);
    assert_eq!(place, state.total, "{what}: each line that left the far end's screen got or said skipped");
    (carried, said)
}

/// The table: each schedule holds the rule at each draw and at its end,
/// and carries lines.
#[test]
fn each_line_that_leaves_the_far_ends_screen_is_got_or_said_skipped() {
    use Output::{Alike, Cleared, Numbered, UpThenFeeds};
    let screens = 3 * u64::from(ROWS) + 2;
    #[rustfmt::skip]
    let table = [
        schedule("a line at a time over a fast link", Numbered(1), 200, 1, 2),
        schedule("a flood over 300 ms", Numbered(5), 400, 1, 30),
        schedule("writes of three screens: rows leave before the last", Numbered(screens), 60, 3, 10),
        schedule("late acknowledgements: frames of one base overlap", Numbered(2), 200, 1, 10).acks(Some(60)),
        schedule("no acknowledgement: the window stays full", Numbered(3), 300, 2, 10).acks(None),
        schedule("rows alike: lines alone, acknowledged late", Alike(3), 200, 2, 20).acks(Some(40)),
        schedule("a cleared screen: fewer rows leave than line feeds", Cleared(9), 100, 4, 5),
        schedule("the cursor up, then line feeds that move no row", UpThenFeeds(8), 100, 3, 5),
        schedule("a road that loses one frame in three", Numbered(4), 200, 2, 10).losing(3),
        schedule("a road that reorders", Numbered(4), 200, 1, 10).acks(Some(5)).reordered(),
        schedule("a whole screen after a lost base", Numbered(4), 200, 2, 10).lost_at(50),
    ];
    for s in &table {
        let (carried, said) = run(s);
        assert!(carried > 0, "{}: no line carried ({said} said skipped)", s.what);
    }
}
