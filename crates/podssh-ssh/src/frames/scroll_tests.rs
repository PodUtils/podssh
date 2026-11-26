//! The lines that leave the top of the far end's screen (T-303), with no
//! I/O: a far end (its model and its sender), a receiver, and a terminal
//! that keeps each row that leaves its top, as a terminal's scrollback.
//! The rule of each case of the table: each line that the far end printed
//! is in the terminal's scrollback or on its screen once, in order, or
//! counted in a line that says it was skipped; none is shown twice.

use std::num::NonZeroU16;
use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::frames::receiver::Receiver;
use crate::frames::screen::{after_block, Model};
use crate::frames::sender::{Sender, COLLECT, PATIENCE};
use crate::frames::wire::{encode, Ack, Version};

const ROWS: u16 = 4;
const COLS: u16 = 40;

fn dim(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap()
}

/// Each row that leaves the top of the primary screen, as its text.
#[derive(Default)]
struct Kept(Vec<String>);

impl vt100::Callbacks for Kept {
    fn on_scroll(&mut self, row: vt100::capture::RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        let mut text = String::new();
        let _ = row.write_formatted_basic(&mut text, &mut vt100::capture::BasicFormattedCaptureState::new());
        self.0.push(vt100::capture::basic_formatted_to_plain(&text).collect());
    }
}

/// The client's terminal, with its scrollback.
struct Terminal(vt100::Parser<Kept>);

impl Terminal {
    fn new() -> Terminal {
        Terminal(vt100::Parser::new_with_callbacks(dim(ROWS), dim(COLS), 0, Kept::default()))
    }

    /// What a person reads, top to bottom: the scrollback, then the screen.
    fn read(&self) -> Vec<String> {
        let mut all = self.0.callbacks().0.clone();
        all.extend(self.0.screen().rows(0, COLS));
        all
    }
}

/// The far end: its pty's model and its sender, on a clock that each frame
/// moves past every wait, and the count of lines that it printed.
struct Far {
    model: Model,
    sender: Sender,
    now: Instant,
    printed: u64,
    version: Version,
}

impl Far {
    fn new(version: Version) -> Far {
        let model = Model::new(ROWS, COLS, false);
        Far { model, sender: Sender::default(), now: Instant::now(), printed: 0, version }
    }

    /// The pty prints `count` numbered lines.
    fn print(&mut self, count: u64) {
        for _ in 0..count {
            self.printed += 1;
            self.model.feed(format!("line {}\r\n", self.printed).as_bytes());
        }
    }

    /// The frame of the screen now, with the lines after its base.
    fn frame(&mut self) -> Vec<u8> {
        self.sender.changed(self.now);
        self.now += PATIENCE + COLLECT;
        let (head, body) = self.sender.frame(&self.model.state(), false, self.now).expect("a frame is due");
        encode(self.version, head, &self.model.lines_after(self.sender.since()), &body)
    }

    /// The last frame, after the output ended.
    fn last(&mut self) -> Vec<u8> {
        self.now += Duration::from_millis(10);
        let (head, body) = self.sender.last(&self.model.state(), false, self.now);
        encode(self.version, head, &self.model.lines_after(self.sender.since()), &body)
    }

    fn acked(&mut self, ack: Ack) {
        self.now += Duration::from_millis(10);
        self.sender.acked(ack, self.now);
    }
}

/// The rule of the file on what a person reads: each line from 1 to
/// `printed` once and in order, or counted as skipped. The count of lines
/// said skipped.
fn each_line_once(read: &[String], printed: u64, what: &str) -> u64 {
    let (mut next, mut skipped) = (1u64, 0u64);
    for row in read {
        let said = row.strip_prefix("[podssh: ").and_then(|rest| rest.split(' ').next()?.parse::<u64>().ok());
        if let Some(count) = said {
            next += count;
            skipped += count;
            continue;
        }
        if let Some(n) = row.strip_prefix("line ").and_then(|n| n.trim_end().parse::<u64>().ok()) {
            assert_eq!(n, next, "{what}: line {n} where line {next} was due: {read:?}");
            next += 1;
        }
    }
    assert_eq!(next, printed + 1, "{what}: each line shown or counted: {read:?}");
    skipped
}

/// One table: what the far end prints before each frame, whether the
/// client acknowledges each frame, whether the frames come in one read,
/// and the count of lines said skipped.
#[test]
fn each_line_is_in_the_scrollback_once_or_counted_as_skipped() {
    let cases: &[(&str, &[u64], bool, bool, u64)] = &[
        ("a line at a time", &[1; 12], true, false, 0),
        ("a screen at a time", &[4, 4, 4, 4], true, false, 0),
        ("more than a screen between two frames", &[3, 50, 2, 9], true, false, 51),
        ("no acknowledgement: each frame from no base", &[2, 2, 2, 2], false, false, 0),
        ("the frames of one read", &[3, 3, 3, 3], false, true, 0),
        ("a flood with no acknowledgement", &[30, 30, 30], false, false, 75),
        ("a flood, acknowledged", &[30, 30, 30], true, false, 75),
    ];
    for (what, prints, acks, one_read, skipped) in cases {
        let (mut far, mut near, mut term) = (Far::new(Version::Two), Receiver::default(), Terminal::new());
        let mut read = Vec::new();
        for count in *prints {
            far.print(*count);
            read.extend_from_slice(&far.frame());
            if !one_read {
                term.0.process(&near.feed(&read).unwrap());
                read.clear();
                let ack = near.take_ack().expect("an acknowledgement is due");
                if *acks {
                    far.acked(ack);
                }
            }
        }
        read.extend_from_slice(&far.last());
        term.0.process(&near.feed(&read).unwrap());
        assert!(near.ended(), "{what}: the last frame came");
        assert_eq!(term.0.screen().contents(), far.model.state().screen.contents(), "{what}: the screen");
        assert_eq!(each_line_once(&term.read(), far.printed, what), *skipped, "{what}: the count skipped");
    }
}

/// Frames of version 1 carry no line: the scrollback gets none, says
/// nothing skipped, and the screen is the far end's.
#[test]
fn frames_of_version_1_put_no_line_in_the_scrollback() {
    let (mut far, mut near, mut term) = (Far::new(Version::One), Receiver::default(), Terminal::new());
    for count in [3, 9, 2] {
        far.print(count);
        term.0.process(&near.feed(&far.frame()).unwrap());
        far.acked(near.take_ack().unwrap());
    }
    let kept = &term.0.callbacks().0;
    assert!(kept.iter().all(String::is_empty), "only the blank rows that the first frame moved up: {kept:?}");
    assert_eq!(term.0.screen().contents(), far.model.state().screen.contents());
}

/// After a line of podssh's own, the lines still go up first, and the
/// screen is drawn whole after them.
#[test]
fn a_disturbed_terminal_gets_its_lines_then_the_whole_screen() {
    let (mut far, mut near, mut term) = (Far::new(Version::Two), Receiver::default(), Terminal::new());
    far.print(2);
    term.0.process(&near.feed(&far.frame()).unwrap());
    far.acked(near.take_ack().unwrap());
    term.0.process(b"\x1b[2;5Hpodssh: a line of its own");
    near.disturbed();
    far.print(4);
    term.0.process(&near.feed(&far.frame()).unwrap());
    assert_eq!(term.0.screen().contents(), far.model.state().screen.contents());
    assert_eq!(each_line_once(&term.read(), far.printed, "disturbed"), 0);
}

/// The far end counts each row that leaves the top of its primary screen
/// and keeps the newest, one screen of them: not the rows of the alternate
/// screen, nor those that a new size moves.
#[test]
fn the_far_end_counts_the_rows_that_leave_its_primary_screen() {
    let mut model = Model::new(ROWS, COLS, false);
    let numbered = |from: u64, to: u64| (from..=to).map(|n| format!("line {n}").into_bytes()).collect::<Vec<_>>();
    for n in 1..=10 {
        model.feed(format!("line {n}\r\n").as_bytes());
    }
    assert_eq!(model.state().total, 7);
    let cases: &[(u64, u64, u64)] = &[(0, 4, 7), (3, 4, 7), (5, 6, 7), (6, 7, 7)];
    for (since, from, to) in cases {
        assert_eq!(model.lines_after(*since), numbered(*from, *to), "after {since}");
    }
    assert!(model.lines_after(7).is_empty() && model.lines_after(70).is_empty());
    model.feed(b"\x1b[?1049h");
    for n in 1..=10 {
        model.feed(format!("alt {n}\r\n").as_bytes());
    }
    model.feed(b"\x1b[?1049l");
    assert_eq!(model.state().total, 7, "the alternate screen's rows");
    model.resize(2, COLS);
    model.resize(ROWS + 2, COLS);
    assert_eq!(model.state().total, 7, "the rows that a new size moves");
    model.feed(b"\x1b[31mred\x1b[m and plain\r\n".repeat(8).as_slice());
    let last = model.lines_after(7).pop().expect("a line");
    assert_eq!(clean(&last), last, "a line of colours is clean as it is");
    let text = String::from_utf8_lossy(&last);
    let plain: String = vt100::capture::basic_formatted_to_plain(&text).collect();
    assert_eq!(plain, "red and plain", "{text:?}");
    assert!(last.starts_with(b"\x1b[") && last.ends_with(b"\x1b[m"), "its colours, then plain: {text:?}");
}

/// Where the last part of a write that holds a number of line feeds
/// starts: one table of writes, the count asked, and the place.
#[test]
fn the_last_part_of_a_write_holds_one_screen_of_line_feeds() {
    let cases: &[(&[u8], usize, usize)] = &[
        (b"", 4, 0),
        (b"no line feed", 4, 0),
        (b"a\nb\n", 4, 0),
        (b"a\nb\nc\nd\n", 4, 0),
        (b"a\nb\nc\nd\ne\n", 4, 2),
        (b"a\r\nb\x0bc\x0cd\ne", 2, 5),
        (b"\n\n\n", 0, 3),
    ];
    for (bytes, lines, at) in cases {
        assert_eq!(tail(bytes, *lines), *at, "{:?}, {lines}", String::from_utf8_lossy(bytes));
    }
}

/// A write of many lines formats only the rows that can be the newest: the
/// newest screen of them is kept, each before it counted alone. Where the
/// newest rows left before the write's last line feeds, none is kept, and
/// the client says them skipped. One table: the write, the count of lines,
/// and the lines kept.
#[test]
fn a_write_keeps_only_the_rows_that_can_be_the_newest() {
    let numbered: String = (1..=100).map(|n| format!("line {n}\r\n")).collect();
    let lines = |from: u64, to: u64| (from..=to).map(|n| format!("line {n}").into_bytes()).collect::<Vec<_>>();
    let cases: Vec<(&str, String, u64, Vec<Vec<u8>>)> = vec![
        ("a hundred lines in one write", numbered.clone(), 97, lines(94, 97)),
        ("then line feeds that scroll nothing", format!("{numbered}\x1b[H\n\n\n\x1b[H\n"), 97, vec![]),
        ("fewer line feeds than a screen", "line 1\r\nline 2\r\nline 3\r\nline 4\r\nli".into(), 1, lines(1, 1)),
    ];
    for (what, write, total, kept) in cases {
        let mut model = Model::new(ROWS, COLS, false);
        model.feed(write.as_bytes());
        assert_eq!(model.state().total, total, "{what}: each row that left is counted");
        assert_eq!(model.lines_after(0), kept, "{what}");
    }
    // A write cut inside a sequence and a character reads as one.
    let (mut whole, mut cut) = (Model::new(ROWS, COLS, false), Model::new(ROWS, COLS, false));
    let write = format!("{numbered}\x1b[31mcaf\u{e9}\x1b[m\r\n").into_bytes();
    whole.feed(&write);
    let at = write.len() - 8;
    cut.feed(&write[..at]);
    cut.feed(&write[at..]);
    assert!(whole.state().same(&cut.state()), "the parser's state crosses the cut");
    assert_eq!(whole.lines_after(0), cut.lines_after(0));
}

/// The lines of one frame stay under the most bytes, the newest kept; a
/// line longer than the most of a line is cut at a character.
#[test]
fn the_lines_of_a_frame_stay_under_the_most_bytes() {
    let (rows, cols) = (20u16, 400u16);
    let mut model = Model::new(rows, cols, false);
    // Two digits, then each cell of its own colour and a character of two
    // bytes, to the last column: a row far above the most of a line.
    let row: String = (0..cols - 2).map(|n| format!("\x1b[38;5;{}m\u{e9}", n % 256)).collect();
    for n in 0..40 {
        model.feed(format!("{n:02}{row}\x1b[m\r\n").as_bytes());
    }
    let lines = model.lines_after(0);
    let bytes: usize = lines.iter().map(Vec::len).sum();
    assert!(!lines.is_empty() && bytes <= BYTES_MOST, "{} lines, {bytes} bytes", lines.len());
    assert!(lines.iter().all(|line| line.len() <= LINE_MOST && std::str::from_utf8(line).is_ok()));
    // The line counted `total` is the one printed with the number `total - 1`.
    let newest = format!("{:02}", model.state().total - 1);
    assert!(lines.last().unwrap().starts_with(newest.as_bytes()), "the newest last");
}

/// What the client keeps and takes: one table of steps, each a frame's
/// count and its lines, then the count drawn and the rows written.
#[test]
fn the_client_writes_each_line_once_and_counts_each_gap() {
    let line = |n: u64| format!("l{n}").into_bytes();
    let lines = |from: u64, to: u64| (from..=to).map(line).collect::<Vec<_>>();
    let gap = |n: u64| skipped(n, COLS);
    let (mut pending, mut drawn) = (Pending::default(), 0);
    // (what, the lines a frame carries with the far end's count, the count after, the lines written)
    type Step<'a> = (&'a str, Option<(u64, Vec<Vec<u8>>)>, u64, Vec<Vec<u8>>);
    let steps: Vec<Step> = vec![
        ("the last lines of five", Some((5, lines(3, 5))), 5, [vec![gap(2)], lines(3, 5)].concat()),
        ("lines that came before are passed over", Some((7, lines(4, 7))), 7, lines(6, 7)),
        ("nothing new", None, 7, vec![]),
        ("a count with no line", None, 10, vec![gap(3)]),
        ("a frame of version 1", Some((0, vec![])), 0, vec![]),
        ("lines that run past the draw wait for the next", Some((14, lines(11, 14))), 12, lines(11, 12)),
        ("and come then", None, 14, lines(13, 14)),
    ];
    for (what, frame, total, want) in steps {
        if let Some((count, carried)) = frame {
            pending.insert(count, carried);
        }
        assert_eq!(pending.take(total, COLS), want, "{what}");
        drawn = total.max(drawn);
        assert_eq!(pending.written(), drawn, "{what}");
    }
    assert_eq!(skipped(1, COLS), b"\x1b[2m[podssh: 1 line skipped]\x1b[m");
    assert_eq!(skipped(123_456, 12), b"\x1b[2m[podssh: 123\x1b[m", "cut to the columns");
}

/// A line of the far end never moves the cursor out of its row: one table
/// of lines and what of each is written.
#[test]
fn a_line_keeps_its_colours_and_no_other_control() {
    let cases: &[(&str, &[u8], &str)] = &[
        ("plain text", b"plain text", "plain text"),
        ("colours", b"\x1b[1;31mred\x1b[m \x1b[38:5:2mgreen\x1b[0m", "\x1b[1;31mred\x1b[m \x1b[38:5:2mgreen\x1b[0m"),
        ("a move of the cursor", b"a\x1b[2;3Hb", "ab"),
        ("a private mode", b"a\x1b[?25lb", "ab"),
        ("an erase", b"a\x1b[2Jb\x1b[K", "ab"),
        ("line feeds, a bell, a tab", b"a\r\n\x07\tb\x7f", "ab"),
        ("a lone escape", b"a\x1bcb\x1b", "acb"),
        ("a C1 control", "a\u{9b}2Jb".as_bytes(), "a2Jb"),
        ("bytes that are no UTF-8", b"a\xffb", "a\u{fffd}b"),
        ("a sequence cut at its end", b"a\x1b[31", "a"),
    ];
    for (what, line, want) in cases {
        assert_eq!(String::from_utf8(clean(line)).unwrap(), *want, "{what}");
    }
}

/// The rows of a block go into a terminal's scrollback in order, a screen
/// at a time, and the model of what the terminal shows after it is right.
#[test]
fn a_block_moves_its_rows_into_the_scrollback_in_order() {
    let mut model = Model::new(ROWS, COLS, false);
    model.feed(b"a\r\nb\r\nc\r\nd");
    let shown = model.state();
    for count in [1u64, 3, 4, 5, 9] {
        let mut term = Terminal::new();
        term.0.process(b"a\r\nb\r\nc\r\nd");
        let rows: Vec<Vec<u8>> = (1..=count).map(|n| format!("row {n}").into_bytes()).collect();
        let moved = block(&rows, ROWS);
        term.0.process(&moved);
        let want: Vec<String> = (1..=count).map(|n| format!("row {n}")).collect();
        assert_eq!(term.0.callbacks().0, want, "{count} rows");
        let after = after_block(&shown, &moved);
        assert_eq!(after.screen.contents(), term.0.screen().contents(), "the model after {count} rows");
        assert_eq!(after.screen.cursor_position(), term.0.screen().cursor_position(), "the cursor after {count} rows");
    }
}
