//! The engine against rows that a table gives: what shows after each key
//! and each report, with no terminal and no clock but the table's.

use super::*;

const COLS: u16 = 20;
const SLOW: Duration = Duration::from_millis(300);
const ECHOING: Flags = Flags { echo: true, canonical: true };
const RAW: Flags = Flags { echo: false, canonical: false };
const HIDDEN: Flags = Flags { echo: false, canonical: true };

/// Row 0 showing `text`, the cursor at `cursor`.
fn line(text: &str, cursor: u16) -> Line {
    let mut cells: Vec<Option<String>> = text.chars().map(|c| Some(c.to_string())).collect();
    cells.resize(usize::from(COLS), Some(String::new()));
    Line { row: 0, cursor, cols: COLS, cells, hidden_cursor: false }
}

/// The row as it shows with the guesses drawn over it, and the cursor.
fn drawn(engine: &Engine, under: &Line) -> (String, u16) {
    let mut cells: Vec<String> = under.cells.iter().map(|c| c.clone().unwrap_or_default()).collect();
    let mut cursor = under.cursor;
    if let Some((guessed, at)) = engine.shown(under) {
        for (col, text) in guessed {
            cells[usize::from(col)] = text;
        }
        cursor = at;
    }
    let text: String = cells.iter().map(|c| if c.is_empty() { " " } else { c.as_str() }).collect();
    (text.trim_end().to_string(), cursor)
}

/// One step of a run: keys sent, or a report with the screen after it.
enum Step<'a> {
    Keys(&'a [u8]),
    Report(u64, Flags, &'a str, u16),
}

/// The runs: each step, then the row and cursor that show after it.
#[test]
fn what_shows_after_each_step_is_what_the_table_says() {
    type Row<'a> = (&'a str, Duration, Flags, &'a [(Step<'a>, &'a str, u16)]);
    let runs: &[Row<'_>] = &[
        ("a first guess waits for its echo, the next shows at once", SLOW, ECHOING, &[
            (Step::Keys(b"l"), "$", 2),
            (Step::Report(1, ECHOING, "$ l", 3), "$ l", 3),
            (Step::Keys(b"s"), "$ ls", 4),
            (Step::Keys(b"\x7f"), "$ l", 3),
            (Step::Report(3, ECHOING, "$ l", 3), "$ l", 3),
        ]),
        ("a line with no echo shows no guess, even in a confirmed epoch", SLOW, ECHOING, &[
            (Step::Keys(b"a"), "$", 2),
            (Step::Report(1, ECHOING, "$ a", 3), "$ a", 3),
            (Step::Report(1, HIDDEN, "$ a", 3), "$ a", 3),
            (Step::Keys(b"pw"), "$ a", 3),
            (Step::Report(3, HIDDEN, "$ a", 3), "$ a", 3),
            (Step::Keys(b"d"), "$ a", 3),
        ]),
        ("a wrong guess goes with its report, and the next waits again", SLOW, RAW, &[
            (Step::Keys(b"a"), "$", 2),
            (Step::Report(1, RAW, "$ a", 3), "$ a", 3),
            (Step::Keys(b"b"), "$ ab", 4),
            (Step::Report(2, RAW, "$ a*", 4), "$ a*", 4),
            (Step::Keys(b"c"), "$ a*", 4),
        ]),
        ("text after the cursor moves as a line editor moves it", SLOW, RAW, &[
            (Step::Keys(b"x"), "$ ac", 3),
            (Step::Report(1, RAW, "$ axc", 4), "$ axc", 4),
            (Step::Keys(b"b"), "$ axbc", 5),
            (Step::Keys(b"\x1b[D\x1b[D\x7f"), "$ xbc", 2),
            (Step::Keys(b"\x1b[C"), "$ xbc", 3),
        ]),
        ("Enter starts an epoch that shows nothing until its echo", SLOW, ECHOING, &[
            (Step::Keys(b"a"), "$", 2),
            (Step::Report(1, ECHOING, "$ a", 3), "$ a", 3),
            (Step::Keys(b"\r"), "$ a", 3),
            (Step::Keys(b"b"), "$ a", 3),
        ]),
        ("below the round trip's line nothing shows", Duration::from_millis(20), ECHOING, &[
            (Step::Keys(b"a"), "$", 2),
            (Step::Report(1, ECHOING, "$ a", 3), "$ a", 3),
            (Step::Keys(b"b"), "$ a", 3),
        ]),
    ];
    for (name, rtt, flags, steps) in runs {
        let start = Instant::now();
        let mut engine = Engine::new(*rtt);
        // The prompt, and the far end's first word.
        let mut screen = if name.starts_with("text after") { line("$ ac", 3) } else { line("$", 2) };
        engine.report(Report { offset: 0, flags: *flags }, &screen, start);
        for (i, (step, row, cursor)) in steps.iter().enumerate() {
            // The table's own clock: the round trip that the run names.
            let now = start + *rtt * (i as u32 + 1) + ECHO_WAIT;
            match step {
                Step::Keys(data) => engine.keys(data, &screen, now - *rtt - ECHO_WAIT),
                Step::Report(offset, flags, text, at) => {
                    screen = line(text, *at);
                    engine.report(Report { offset: *offset, flags: *flags }, &screen, now);
                }
            }
            assert_eq!(drawn(&engine, &screen), (row.to_string(), *cursor), "{name}: step {i}");
        }
    }
}

/// A report of bytes never sent stops local echo for the session; so does
/// a paste, for its own keys.
#[test]
fn a_far_end_that_counts_wrong_stops_it_and_a_paste_is_not_guessed() {
    let now = Instant::now();
    let mut engine = Engine::new(SLOW);
    let screen = line("$", 2);
    engine.report(Report { offset: 0, flags: ECHOING }, &screen, now);
    engine.keys(&[b'a'; PASTE + 1], &screen, now);
    assert!(engine.shown(&screen).is_none());
    engine.report(Report { offset: 1000, flags: ECHOING }, &screen, now);
    assert!(engine.stopped());
    engine.keys(b"b", &screen, now);
    assert!(engine.shown(&screen).is_none());
}
