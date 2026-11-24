//! The guesses of local echo on the terminal (T-160): drawn over the far
//! end's screen, and taken off again before the far end's next bytes, so
//! that the terminal reads those bytes on the screen that the far end
//! wrote. The model of that screen is never written.
//!
//! Each move is relative, along the cursor's row (`CSI n C`, `CSI n D`):
//! an absolute place would be read inside the scrolling region under the
//! origin mode, which the model does not tell. Nothing is drawn in the last
//! column, so no wrap waits, and the pen is the model's again after each
//! drawing.

use std::fmt::Write as _;

use vt100::{Cell, Color, Screen};

/// What a guess shows in: the far end's pen, underlined.
const GUESSED: &str = "\x1b[4m";

/// What is drawn over the screen now: the columns of the cursor's row, and
/// the column that the terminal's cursor was left in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Shown {
    cols: Vec<u16>,
    at: u16,
}

/// Move along the row from `from` to `to`.
fn step(out: &mut String, from: u16, to: u16) {
    if to > from {
        let _ = write!(out, "\x1b[{}C", to - from);
    } else if to < from {
        let _ = write!(out, "\x1b[{}D", from - to);
    }
}

/// Draw `cells` over `screen`'s cursor row, and leave the cursor at
/// `cursor`. The terminal must show `screen` as it is, with its cursor.
pub(super) fn draw(screen: &Screen, cells: &[(u16, String)], cursor: u16) -> (Vec<u8>, Shown) {
    let (_, mut at) = screen.cursor_position();
    let pen = screen.attributes_formatted();
    let mut out = String::new();
    for (col, text) in cells {
        step(&mut out, at, *col);
        out.push_str(&pen);
        out.push_str(GUESSED);
        out.push_str(if text.is_empty() { " " } else { text });
        at = col + 1;
    }
    if !cells.is_empty() {
        out.push_str(&pen);
    }
    step(&mut out, at, cursor);
    (out.into_bytes(), Shown { cols: cells.iter().map(|c| c.0).collect(), at: cursor })
}

/// Take `shown` off `screen`'s cursor row: each cell as the screen has it,
/// then the pen and the cursor as the far end left them.
pub(super) fn undo(screen: &Screen, shown: &Shown) -> Vec<u8> {
    let (row, to) = screen.cursor_position();
    let mut at = shown.at;
    let mut out = String::new();
    for &col in &shown.cols {
        step(&mut out, at, col);
        let cell = screen.cell(row, col);
        out.push_str(&sgr(cell));
        match cell.map(Cell::contents).filter(|t| !t.is_empty()) {
            Some(text) => {
                out.push_str(text);
                at = col + 1;
            }
            // An empty cell is erased again (ECH), with its own colors; a
            // space would be text where the far end left none.
            None => {
                out.push_str("\x1b[1X");
                at = col;
            }
        }
    }
    if !shown.cols.is_empty() {
        out.push_str(&screen.attributes_formatted());
    }
    step(&mut out, at, to);
    out.into_bytes()
}

/// The pen of `cell`, from a reset.
fn sgr(cell: Option<&Cell>) -> String {
    let mut out = String::from("\x1b[0");
    if let Some(c) = cell {
        for (on, code) in [(c.bold(), 1), (c.dim(), 2), (c.italic(), 3), (c.underline(), 4), (c.inverse(), 7)] {
            if on {
                let _ = write!(out, ";{code}");
            }
        }
        color(&mut out, c.fgcolor(), 30, 90, 38);
        color(&mut out, c.bgcolor(), 40, 100, 48);
    }
    out.push('m');
    out
}

/// One color of a pen: its base code for the first 8, its bright code for
/// the next 8, and the extended code for the rest and for RGB.
fn color(out: &mut String, color: Color, base: u8, bright: u8, extended: u8) {
    match color {
        Color::Default => {}
        Color::Idx(i) if i < 8 => {
            let _ = write!(out, ";{}", base + i);
        }
        Color::Idx(i) if i < 16 => {
            let _ = write!(out, ";{}", bright + i - 8);
        }
        Color::Idx(i) => {
            let _ = write!(out, ";{extended};5;{i}");
        }
        Color::Rgb(r, g, b) => {
            let _ = write!(out, ";{extended};2;{r};{g};{b}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(bytes: &[u8]) -> vt100::Parser {
        let size = |n| std::num::NonZeroU16::new(n).unwrap();
        let mut p = vt100::Parser::new(size(4), size(20), 0);
        p.process(bytes);
        p
    }

    /// A drawing and its undo leave a terminal that read the far end's
    /// bytes exactly as the far end's own screen: cells, pens and cursor.
    #[test]
    fn an_undo_leaves_the_screen_and_the_pen_of_the_far_end() {
        let far = b"\x1b[1;31m$\x1b[0m \x1b[44mab\x1b[7m";
        let model = screen(far);
        let mut terminal = screen(far);
        let (drawn, shown) = draw(model.screen(), &[(3, "x".into()), (4, "b".into()), (6, String::new())], 5);
        terminal.process(&drawn);
        assert_eq!(terminal.screen().cursor_position(), (0, 5));
        assert!(terminal.screen().cell(0, 3).is_some_and(|c| c.contents() == "x" && c.underline()));
        assert_eq!(terminal.screen().attributes_formatted(), model.screen().attributes_formatted());
        terminal.process(&undo(model.screen(), &shown));
        assert_eq!(terminal.screen().contents_formatted(), model.screen().contents_formatted());
        assert_eq!(terminal.screen().cursor_position(), model.screen().cursor_position());
        assert_eq!(terminal.screen().attributes_formatted(), model.screen().attributes_formatted());
        // The far end's next bytes land where they would have.
        terminal.process(b"c");
        let mut after = screen(far);
        after.process(b"c");
        assert_eq!(terminal.screen().contents_formatted(), after.screen().contents_formatted());
    }
}
