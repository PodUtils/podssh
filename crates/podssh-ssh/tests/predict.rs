//! Local echo (T-160) against a far end in the test, through a link whose
//! round trip the test sets, on the clock of the test: the terminal oracle
//! (T-200's model, `vt100`) reads each byte that podssh writes, and a
//! second model reads the far end's bytes alone. After each step, each row
//! but the cursor's is the far end's own, and each cell of the cursor's row
//! that differs is a guess, underlined; once each key was answered, the
//! terminal is the far end's screen, cell for cell.
//!
//! At a round trip of 300 ms a typed letter shows before its echo. Where
//! the pty reads a line with no echo, or nothing echoes the keys, no typed
//! letter shows before the far end writes it.

use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use podssh_ssh::predict::report::{encode, Flags, Report};
use podssh_ssh::predict::{Predict, ECHO_WAIT};

const COLS: u16 = 40;
const ROWS: u16 = 6;
const PROMPT: &str = "$ ";

/// What the far end's pty and program do with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The kernel echoes a line (ECHO, ICANON): `cat`, `read`.
    Cooked,
    /// A line editor echoes each key itself, with ECHO off: readline.
    Editor,
    /// A line read with no echo: a question for a password.
    Hidden,
    /// Raw keys that the program shows as `*`.
    Stars,
    /// Raw keys that nothing echoes: vim's normal mode.
    Quiet,
}

impl Mode {
    fn flags(self) -> Flags {
        match self {
            Mode::Cooked => Flags { echo: true, canonical: true },
            Mode::Hidden => Flags { echo: false, canonical: true },
            Mode::Editor | Mode::Stars | Mode::Quiet => Flags { echo: false, canonical: false },
        }
    }
}

enum Event {
    /// Keys reach the far end.
    Keys(Vec<u8>),
    /// The far end's count of this many bytes falls due.
    Due(u64),
    /// The far end's program changes its mode and writes its words.
    Switch(Mode, &'static str),
    /// The far end's output reaches the client.
    Output(Vec<u8>),
    /// A report reaches the client.
    Report(Vec<u8>),
}

/// The far end: a program on a pty, and serve's count of the keys.
struct Far {
    mode: Mode,
    line: Vec<u8>,
    received: u64,
    told: Option<Report>,
}

impl Far {
    /// What the far end writes for `keys`.
    fn read(&mut self, keys: &[u8]) -> Vec<u8> {
        self.received += keys.len() as u64;
        let echoes = matches!(self.mode, Mode::Cooked | Mode::Editor);
        let mut out = Vec::new();
        for &key in keys {
            match key {
                b'\r' => {
                    self.line.clear();
                    out.extend_from_slice(b"\r\n");
                    out.extend_from_slice(PROMPT.as_bytes());
                }
                0x7f if !self.line.is_empty() => {
                    self.line.pop();
                    if echoes {
                        out.extend_from_slice(b"\x08 \x08");
                    }
                }
                0x20..=0x7e => {
                    self.line.push(key);
                    match self.mode {
                        Mode::Cooked | Mode::Editor => out.push(key),
                        Mode::Stars => out.push(b'*'),
                        Mode::Hidden | Mode::Quiet => {}
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// The client, the far end and the link between them, on the test's clock.
struct Sim {
    start: Instant,
    /// One way, in ms.
    half: u64,
    queue: Vec<(u64, u64, Event)>,
    seq: u64,
    far: Far,
    predict: Predict,
    /// Each byte that podssh writes to the terminal.
    terminal: vt100::Parser,
    /// The far end's bytes alone.
    screen: vt100::Parser,
}

fn size(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap()
}

impl Sim {
    /// A session whose round trip is `rtt` ms, its far end in `mode`.
    fn new(mode: Mode, rtt: u64) -> Sim {
        let mut sim = Sim {
            start: Instant::now(),
            half: rtt / 2,
            queue: Vec::new(),
            seq: 0,
            far: Far { mode, line: Vec::new(), received: 0, told: None },
            predict: Predict::new(COLS.into(), ROWS.into(), Duration::from_millis(rtt)),
            terminal: vt100::Parser::new(size(ROWS), size(COLS), 0),
            screen: vt100::Parser::new(size(ROWS), size(COLS), 0),
        };
        sim.push(0, Event::Switch(mode, PROMPT));
        sim
    }

    fn push(&mut self, at: u64, event: Event) {
        self.seq += 1;
        self.queue.push((at, self.seq, event));
    }

    fn instant(&self, ms: u64) -> Instant {
        self.start + Duration::from_millis(ms)
    }

    /// The user types `keys` at `ms`.
    fn type_at(&mut self, ms: u64, keys: &[u8]) {
        self.run_until(ms);
        let shown = self.predict.keys(keys, self.instant(ms));
        self.terminal.process(&shown);
        self.check();
        self.push(ms + self.half, Event::Keys(keys.to_vec()));
    }

    /// The far end's program changes its mode at `ms` (its time).
    fn switch_at(&mut self, ms: u64, mode: Mode, words: &'static str) {
        self.run_until(ms);
        self.push(ms, Event::Switch(mode, words));
        self.run_until(ms);
    }

    /// Each event up to `ms`, the earliest first, and in order of sending.
    fn run_until(&mut self, ms: u64) {
        while let Some(i) = (0..self.queue.len()).min_by_key(|&i| (self.queue[i].0, self.queue[i].1)) {
            if self.queue[i].0 > ms {
                break;
            }
            let (at, _, event) = self.queue.remove(i);
            self.handle(at, event);
        }
    }

    fn handle(&mut self, at: u64, event: Event) {
        match event {
            Event::Keys(keys) => {
                let out = self.far.read(&keys);
                if !out.is_empty() {
                    self.push(at + self.half, Event::Output(out));
                }
                let wait = u64::try_from(ECHO_WAIT.as_millis()).unwrap();
                self.push(at + wait, Event::Due(self.far.received));
            }
            Event::Due(offset) => self.tell(at, Some(offset)),
            Event::Switch(mode, words) => {
                self.far.mode = mode;
                self.far.line.clear();
                self.push(at + self.half, Event::Output(words.as_bytes().to_vec()));
                self.tell(at, None);
            }
            Event::Output(bytes) => {
                self.screen.process(&bytes);
                let shown = self.predict.output(&bytes);
                self.terminal.process(&shown);
                self.check();
            }
            Event::Report(bytes) => {
                let shown = self.predict.report(&bytes, self.instant(at));
                self.terminal.process(&shown);
                self.check();
            }
        }
    }

    /// The far end's report, after its output, where its count or its
    /// flags changed: as `podssh serve` sends it.
    fn tell(&mut self, at: u64, offset: Option<u64>) {
        let offset = offset.or(self.far.told.map(|t| t.offset)).unwrap_or(0);
        let report = Report { offset, flags: self.far.mode.flags() };
        if self.far.told != Some(report) {
            self.far.told = Some(report);
            self.push(at + self.half, Event::Report(encode(report).to_vec()));
        }
    }

    /// The columns of the cursor's row where the terminal shows other than
    /// the far end's screen.
    fn guessed(&self) -> Vec<u16> {
        let (t, s) = (self.terminal.screen(), self.screen.screen());
        let (row, _) = s.cursor_position();
        let look = |c: Option<&vt100::Cell>| {
            c.map(|c| (c.contents().to_string(), c.underline(), c.bold(), c.inverse(), c.fgcolor(), c.bgcolor()))
        };
        (0..COLS).filter(|&col| look(t.cell(row, col)) != look(s.cell(row, col))).collect()
    }

    /// The text of the terminal's row `row`.
    fn row(&self, row: u16) -> String {
        self.terminal.screen().rows(0, COLS).nth(usize::from(row)).unwrap().trim_end().to_string()
    }

    /// The far end's cursor row, as the terminal shows it.
    fn cursor_row(&self) -> String {
        self.row(self.screen.screen().cursor_position().0)
    }

    /// The oracle's rule, after each step.
    fn check(&self) {
        let (t, s) = (self.terminal.screen(), self.screen.screen());
        let (row, _) = s.cursor_position();
        let shown: Vec<String> = t.rows_formatted(0, COLS).collect();
        let own: Vec<String> = s.rows_formatted(0, COLS).collect();
        for r in 0..ROWS {
            if r != row {
                assert_eq!(shown[usize::from(r)], own[usize::from(r)], "row {r}, not the cursor's, is the far end's");
            }
        }
        for col in self.guessed() {
            assert!(t.cell(row, col).is_some_and(vt100::Cell::underline), "a cell that differs is a guess: {col}");
        }
        if self.guessed().is_empty() {
            assert_eq!(t.cursor_position().0, s.cursor_position().0, "the cursor's row");
        }
    }

    /// Once each key was answered: the far end's screen, cell for cell.
    fn settled(&mut self, ms: u64) {
        self.run_until(ms);
        let (t, s) = (self.terminal.screen(), self.screen.screen());
        assert_eq!(t.contents_formatted(), s.contents_formatted());
        assert_eq!(t.cursor_position(), s.cursor_position());
        assert_eq!(t.attributes_formatted(), s.attributes_formatted());
    }

    /// Type `a`, which waits for its echo, then `b`, which shows at once:
    /// the epoch is confirmed. Done by 1500 ms at a round trip of 300 ms.
    fn confirm(&mut self) {
        self.type_at(400, b"a");
        self.type_at(1000, b"b");
        assert_eq!(self.cursor_row(), "$ ab", "a letter of a confirmed epoch shows at once");
        self.settled(1500);
    }
}

#[test]
fn typed_letters_show_before_their_echo_and_go_with_it() {
    let mut sim = Sim::new(Mode::Cooked, 300);
    sim.type_at(400, b"l");
    assert_eq!(sim.cursor_row(), "$", "the first key of an epoch waits for its echo");
    sim.type_at(1000, b"s");
    assert_eq!(sim.cursor_row(), "$ ls", "before its echo");
    assert_eq!(sim.guessed(), vec![3]);
    assert_eq!(sim.terminal.screen().cursor_position(), (0, 4), "the cursor after the guess");
    sim.settled(1500);
    assert!(sim.guessed().is_empty(), "the echo took the guess's place");
    // Backspace shows at once too.
    sim.type_at(1600, b"\x7f");
    assert_eq!(sim.cursor_row(), "$ l");
    assert_eq!(sim.terminal.screen().cursor_position(), (0, 3));
    sim.settled(2200);
}

/// A program that echoes nothing, or a line read with no echo, after a
/// confirmed epoch: no typed letter shows before the far end writes it.
#[test]
fn no_typed_letter_shows_where_the_far_end_echoes_none() {
    // Each change that a program makes when it stops echoing: a question
    // on a new row, or the pty's flags. (A program that stops echoing with
    // neither, and no key between, is guessed for until its next report:
    // `a_wrong_guess_goes_with_its_report`.)
    let rows: &[(Mode, &str)] = &[
        (Mode::Hidden, "\r\nPassword: "),
        (Mode::Hidden, ""),
        (Mode::Stars, "\r\nPIN: "),
        (Mode::Quiet, "\r\n"),
    ];
    for &(mode, words) in rows {
        let mut sim = Sim::new(Mode::Editor, 300);
        sim.confirm();
        sim.switch_at(1500, mode, words);
        let mut at = 2000;
        for key in b"secret" {
            sim.type_at(at, &[*key]);
            assert!(sim.guessed().is_empty(), "{mode:?} {words:?}: {:?} shows nothing of its own", *key as char);
            at += 100;
        }
        sim.settled(4000);
        for row in 0..ROWS {
            let text = sim.row(row);
            assert!(!text.contains("se") && !text.contains('c'), "{mode:?} {words:?}: row {row} is {text:?}");
        }
    }
}

/// A paste, and a round trip under the line, show nothing; the terminal is
/// still the far end's once the keys were answered.
#[test]
fn a_paste_and_a_short_round_trip_show_nothing() {
    let mut sim = Sim::new(Mode::Cooked, 300);
    sim.confirm();
    sim.type_at(1600, &[b'x'; 150]);
    assert!(sim.guessed().is_empty(), "a paste is not guessed");
    sim.settled(2500);

    let mut near = Sim::new(Mode::Cooked, 40);
    for (i, key) in b"abcdef".iter().enumerate() {
        near.type_at(200 + 70 * i as u64, &[*key]);
        assert!(near.guessed().is_empty(), "at 40 ms nothing shows");
    }
    near.settled(1500);
}

/// A program whose echo differs from the guess: the guess goes with the
/// far end's word, and the next key waits again.
#[test]
fn a_wrong_guess_goes_with_its_report() {
    let mut sim = Sim::new(Mode::Editor, 300);
    sim.confirm();
    // The same line editor, now showing each key as `*`, with no change of
    // its flags or its row.
    sim.far.mode = Mode::Stars;
    sim.type_at(1600, b"c");
    assert_eq!(sim.cursor_row(), "$ abc", "a guess of a confirmed epoch shows");
    sim.settled(2100);
    assert_eq!(sim.cursor_row(), "$ ab*", "the far end's echo, and no guess");
    sim.type_at(2200, b"d");
    assert!(sim.guessed().is_empty(), "the next key waits for its echo");
    sim.settled(2800);
}
