//! Local echo's guesses drawn over frames (T-160 over T-303), with no SSH:
//! the far end's model and sender make each frame, the client's receiver
//! draws it, and local echo takes its guesses off before the drawing and
//! puts those that still stand on again after it, as over bytes. The
//! terminal oracle (`vt100`) reads each byte that podssh writes.
//!
//! The far end sends each report of local echo after the frame of the
//! output that it read before the report (`server/frames.rs`), so a step
//! of the table that is a report follows the frame that holds the echo of
//! the keys it counts.

use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use podssh_ssh::frames::receiver::Receiver;
use podssh_ssh::frames::screen::Model;
use podssh_ssh::frames::sender::Sender;
use podssh_ssh::frames::wire::{encode, Version};
use podssh_ssh::predict::report::{encode as report, Flags, Report};
use podssh_ssh::predict::Predict;

const COLS: u16 = 30;
const ROWS: u16 = 5;
const ECHOING: Flags = Flags { echo: true, canonical: true };

/// One step: the far end's program writes, keys go, or a report comes.
#[derive(Debug, Clone, Copy)]
enum Step {
    Far(&'static [u8]),
    Keys(&'static [u8]),
    Report(u64),
}

/// The far end, the client and its terminal, on the test's clock.
struct Ends {
    far: Model,
    sender: Sender,
    receiver: Receiver,
    predict: Predict,
    terminal: vt100::Parser,
    clock: Instant,
    frames: usize,
}

fn dim(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap()
}

impl Ends {
    fn new() -> Ends {
        Ends {
            far: Model::new(ROWS, COLS, true).without_lines(),
            sender: Sender::default(),
            receiver: Receiver::default(),
            // A round trip at which guesses show.
            predict: Predict::new(COLS.into(), ROWS.into(), Duration::from_millis(300)),
            terminal: vt100::Parser::new(dim(ROWS), dim(COLS), 0),
            clock: Instant::now(),
            frames: 0,
        }
    }

    fn step(&mut self, step: Step) {
        // Each step a second later: the pace of the frames never holds one.
        self.clock += Duration::from_secs(1);
        let now = tokio::time::Instant::from_std(self.clock);
        let shown = match step {
            Step::Far(bytes) => {
                self.far.feed(bytes);
                self.sender.changed(now - Duration::from_millis(500));
                let bell = self.far.bell();
                let Some((head, body)) = self.sender.frame(&self.far.state(), bell, now) else { return };
                self.far.clear_bell();
                self.frames += 1;
                let drawn = self.receiver.feed(&encode(Version::One, head, &[], &body)).expect("a frame");
                if let Some(ack) = self.receiver.take_ack() {
                    self.sender.acked(ack, now);
                }
                self.predict.output(&drawn)
            }
            Step::Keys(keys) => self.predict.keys(keys, self.clock),
            Step::Report(offset) => self.predict.report(&report(Report { offset, flags: ECHOING }), self.clock),
        };
        self.terminal.process(&shown);
    }

    /// The terminal's rows with text, joined by `|`.
    fn text(&self) -> String {
        let rows: Vec<String> = self.terminal.screen().rows(0, COLS).map(|r| r.trim_end().to_string()).collect();
        let used = rows.iter().rposition(|r| !r.is_empty()).map_or(0, |i| i + 1);
        rows[..used].join("|")
    }

    /// The underlined cells: the guesses that show.
    fn guessed(&self) -> Vec<(u16, u16)> {
        let screen = self.terminal.screen();
        let mut cells = Vec::new();
        for row in 0..ROWS {
            for col in 0..COLS {
                if screen.cell(row, col).is_some_and(vt100::Cell::underline) {
                    cells.push((row, col));
                }
            }
        }
        cells
    }

    /// Each row but the cursor's is the far end's as the frames gave it:
    /// a guess never lands elsewhere.
    fn rows_beside_the_cursor_are_the_far_ends(&self) -> bool {
        let Some(state) = self.receiver.state() else { return true };
        let (row, _) = self.terminal.screen().cursor_position();
        let ours: Vec<String> = self.terminal.screen().rows(0, COLS).collect();
        let theirs: Vec<String> = state.screen.rows(0, COLS).collect();
        (0..usize::from(ROWS)).filter(|r| *r != usize::from(row)).all(|r| ours[r] == theirs[r])
    }
}

/// After each step: what the terminal shows, the guesses on it, and its
/// cursor. A guess confirmed by a frame stops being drawn (the frame shows
/// it); one that a frame contradicts goes with its report, right after that
/// frame; one still pending when a frame comes is drawn again over it; a
/// frame that moves the cursor to another row ends the guesses of the row.
#[test]
fn the_guesses_over_frames_are_what_the_table_says() {
    #[rustfmt::skip]
    // (the step, what it is, the cells that must match, the cursor after)
    type Row<'a> = (Step, &'a str, &'a [(u16, u16)], (u16, u16));
    let table: &[Row] = &[
        (Step::Far(b"$ "), "$", &[], (0, 2)),
        (Step::Report(0), "$", &[], (0, 2)),
        // The first guess of an epoch waits for the far end's echo.
        (Step::Keys(b"l"), "$", &[], (0, 2)),
        (Step::Far(b"l"), "$ l", &[], (0, 3)),
        (Step::Report(1), "$ l", &[], (0, 3)),
        // In a confirmed epoch a key shows at once, underlined.
        (Step::Keys(b"s"), "$ ls", &[(0, 3)], (0, 4)),
        // Pending when a frame comes (a new title): drawn again over it.
        (Step::Far(b"\x1b]2;work\x07"), "$ ls", &[(0, 3)], (0, 4)),
        // Confirmed: the frame shows the echo, and no guess is drawn.
        (Step::Far(b"s"), "$ ls", &[], (0, 4)),
        (Step::Report(2), "$ ls", &[], (0, 4)),
        // Contradicted: the frame shows another cell, and the report that
        // follows it takes the guess off; the next epoch waits again.
        (Step::Keys(b"x"), "$ lsx", &[(0, 4)], (0, 5)),
        (Step::Far(b"X"), "$ lsx", &[(0, 4)], (0, 5)),
        (Step::Report(3), "$ lsX", &[], (0, 5)),
        (Step::Keys(b"y"), "$ lsX", &[], (0, 5)),
        (Step::Far(b"y"), "$ lsXy", &[], (0, 6)),
        (Step::Report(4), "$ lsXy", &[], (0, 6)),
        (Step::Keys(b"z"), "$ lsXyz", &[(0, 6)], (0, 7)),
        // A frame that moves the cursor to another row: the row's guesses go.
        (Step::Far(b"\r\n$ "), "$ lsXy|$", &[], (1, 2)),
        (Step::Report(5), "$ lsXy|$", &[], (1, 2)),
    ];
    let mut ends = Ends::new();
    for (i, &(step, text, guessed, cursor)) in table.iter().enumerate() {
        ends.step(step);
        let at = format!("step {i}, {step:?}");
        assert_eq!(ends.text(), text, "{at}: the terminal");
        assert_eq!(ends.guessed(), guessed, "{at}: the guesses");
        assert_eq!(ends.terminal.screen().cursor_position(), cursor, "{at}: the cursor");
        assert!(ends.rows_beside_the_cursor_are_the_far_ends(), "{at}: a row beside the cursor's");
    }
    assert_eq!(ends.frames, 7, "each write of the far end made a frame");
    // With no guess left, the terminal is the far end's screen, cell for cell.
    let far = ends.far.state();
    assert_eq!(ends.terminal.screen().contents(), far.screen.contents());
    assert_eq!(ends.terminal.screen().cursor_position(), far.screen.cursor_position());
}
