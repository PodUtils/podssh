//! The model of a screen and the difference of two (T-303): `vt100`, the
//! model of the terminal oracle (T-200) and of local echo (T-160), on each
//! end. The far end's model reads the pty's output; a frame's body is what
//! `vt100` writes to turn one screen into another, and the client's model
//! reads it. Nothing here does I/O.
//!
//! A state is the visible screen, the cursor, the modes of the keys (the
//! application keypad and cursor keys, bracketed paste, the mouse), and the
//! window's title. It holds no scrollback, and the alternate screen is the
//! visible screen while a program has it: the client's terminal never
//! enters it.

use std::num::NonZeroU16;
use std::sync::Arc;

/// The longest title kept; the rest of a longer one is dropped.
pub const TITLE_MOST: usize = 256;
/// The most bytes of answers that wait for the pty; a program that asks
/// more before they are written gets no answer to the rest.
pub const ANSWERS_MOST: usize = 256;

fn dim(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap_or(NonZeroU16::MIN)
}

/// What a model keeps beside its grid: the title, a bell that waits for
/// the next frame, and the answers to the questions that a program asks
/// its terminal, which with frames never reach the client's.
#[derive(Debug, Default)]
pub struct Aside {
    title: Option<Arc<[u8]>>,
    bell: bool,
    answers: Vec<u8>,
    /// Whether this model answers (the far end's does; the client's reads
    /// frames, which ask nothing).
    answering: bool,
}

impl vt100::Callbacks for Aside {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bell = true;
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        // No control byte: the client writes the title inside a sequence.
        let clean: Vec<u8> = title.iter().copied().filter(|b| *b >= 0x20 && *b != 0x7f).take(TITLE_MOST).collect();
        self.title = Some(clean.into());
    }

    /// The questions that programs wait on: the device status and the
    /// cursor's place (`CSI 5 n`, `CSI 6 n`), and the primary device
    /// attributes (`CSI c`), answered as a VT100 with the advanced video
    /// option, the least that xterm ever says.
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        _i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        if !self.answering || i1.is_some() {
            return;
        }
        let first = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        let answer = match (c, first) {
            ('n', 5) => "\x1b[0n".to_string(),
            ('n', 6) => {
                let (rows, cols) = screen.size();
                let (row, col) = screen.cursor_position();
                // A cursor past the last column waits to wrap: it is on it.
                format!("\x1b[{};{}R", row.min(rows.get() - 1) + 1, col.min(cols.get() - 1) + 1)
            }
            ('c', 0) => "\x1b[?1;2c".to_string(),
            _ => return,
        };
        if self.answers.len() + answer.len() <= ANSWERS_MOST {
            self.answers.extend_from_slice(answer.as_bytes());
        }
    }
}

/// One screen, as a frame carries it.
#[derive(Debug, Clone)]
pub struct State {
    pub screen: vt100::Screen,
    /// The window's title, once a program set one.
    pub title: Option<Arc<[u8]>>,
}

impl State {
    /// The rows and the columns.
    pub fn size(&self) -> (u16, u16) {
        let (rows, cols) = self.screen.size();
        (rows.get(), cols.get())
    }

    /// Whether `other` is the same screen: the same title, and nothing
    /// that a terminal showing one would need to become the other.
    pub fn same(&self, other: &State) -> bool {
        self.title == other.title && self.size() == other.size() && self.screen.state_diff(&other.screen).is_empty()
    }
}

/// The far end's model of its screen.
pub struct Model {
    parser: vt100::Parser<Aside>,
}

impl Model {
    /// An empty screen of `rows` by `cols`, as a new pty's terminal is.
    /// With `answering`, it answers the questions of [`Aside`].
    pub fn new(rows: u16, cols: u16, answering: bool) -> Model {
        let aside = Aside { answering, ..Aside::default() };
        Model { parser: vt100::Parser::new_with_callbacks(dim(rows), dim(cols), 0, aside) }
    }

    /// The pty's output.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// A new size of the pty.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.parser.set_size(dim(rows), dim(cols));
    }

    /// The screen now.
    pub fn state(&self) -> State {
        State { screen: self.parser.screen().clone(), title: self.parser.callbacks().title.clone() }
    }

    /// Whether the bell rang since [`Model::clear_bell`].
    pub fn bell(&self) -> bool {
        self.parser.callbacks().bell
    }

    /// The bell went into a frame.
    pub fn clear_bell(&mut self) {
        self.parser.callbacks_mut().bell = false;
    }

    /// The answers that wait for the pty, taken.
    pub fn take_answers(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.parser.callbacks_mut().answers)
    }

    /// Whether answers wait for the pty.
    pub fn answers_wait(&self) -> bool {
        !self.parser.callbacks().answers.is_empty()
    }
}

/// The title of `state` as a sequence that a model and a terminal read.
fn title_into(out: &mut Vec<u8>, title: Option<&[u8]>) {
    if let Some(title) = title {
        out.extend_from_slice(b"\x1b]2;");
        out.extend_from_slice(title);
        out.push(0x07);
    }
}

/// The body of a frame that turns a model of `base` into `new`, and
/// whether it draws the whole screen: with no base, or with a base of
/// another size, which `vt100` does not compare.
pub fn diff(base: Option<&State>, new: &State) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    match base.filter(|base| base.size() == new.size()) {
        Some(base) => {
            if base.title != new.title {
                title_into(&mut body, new.title.as_deref());
            }
            body.extend_from_slice(new.screen.state_diff(&base.screen).as_bytes());
            (body, false)
        }
        None => {
            title_into(&mut body, new.title.as_deref());
            body.extend_from_slice(new.screen.state_formatted().as_bytes());
            (body, true)
        }
    }
}

/// The state that `body` makes of `base` in a model of `rows` by `cols`;
/// with no base, of an empty screen. The caller holds the base's size to
/// the frame's.
pub fn apply(base: Option<&State>, rows: u16, cols: u16, body: &[u8]) -> State {
    let aside = Aside { title: base.and_then(|base| base.title.clone()), ..Aside::default() };
    let mut parser = vt100::Parser::new_with_callbacks(dim(rows), dim(cols), 0, aside);
    if let Some(base) = base {
        *parser.screen_mut() = base.screen.clone();
    }
    parser.process(body);
    State { screen: parser.screen().clone(), title: parser.callbacks().title.clone() }
}

/// What a terminal that shows `shown` needs to show `new`. With `repaint`
/// (the terminal's cursor or content is not known to be `shown`'s: a line
/// of podssh's own, a new size) or with none shown, the whole screen is
/// drawn again from its first cell; the modes of the keys still go as their
/// difference, where the last ones are known.
pub fn draw(shown: Option<&State>, new: &State, repaint: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if shown.map(|shown| &shown.title) != Some(&new.title) {
        title_into(&mut out, new.title.as_deref());
    }
    match shown.filter(|shown| !repaint && shown.size() == new.size()) {
        Some(shown) => out.extend_from_slice(new.screen.state_diff(&shown.screen).as_bytes()),
        None => {
            out.extend_from_slice(new.screen.contents_formatted().as_bytes());
            let modes = match shown {
                Some(shown) => new.screen.input_mode_diff(&shown.screen),
                None => new.screen.input_mode_formatted(),
            };
            out.extend_from_slice(modes.as_bytes());
        }
    }
    out
}

/// What gives a terminal that shows `shown` back to its user at the end:
/// the modes of the keys as a new terminal has them, the cursor shown, and
/// no attribute. The screen stays as the session left it.
pub fn leave(shown: &State) -> Vec<u8> {
    let (rows, cols) = shown.screen.size();
    let plain = vt100::Parser::new(rows, cols, 0);
    let mut out = plain.screen().input_mode_diff(&shown.screen).into_bytes();
    if shown.screen.hide_cursor() {
        out.extend_from_slice(b"\x1b[?25h");
    }
    out.extend_from_slice(b"\x1b[m");
    out
}

#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
