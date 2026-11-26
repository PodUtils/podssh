//! The lines that leave the top of the far end's screen (T-303), so that
//! the client's terminal keeps them in its scrollback as with each byte;
//! no I/O.
//!
//! The far end counts each line that leaves the top of its primary screen
//! and keeps the newest ones, one screen of them ([`Lines`]). Counting a
//! line costs nothing; keeping one costs its formatting, so the far end
//! keeps only those that can be the newest: of each write of the pty, it
//! formats the rows that leave the top in the last part that holds one
//! screen of line feeds ([`tail`]). A flood then costs, for each byte, what
//! it cost with no lines, and each write at most one screen of rows. A
//! frame
//! carries those after the state that it starts from, at most one screen
//! and [`BYTES_MOST`]; the rest of a flood is said as a count. The client
//! keeps the lines that came ([`Pending`]) and, before it draws a state,
//! writes those after the state that its terminal shows: each one in a row
//! at the top of the screen, then as many line feeds at the bottom, so
//! that the terminal itself moves them into its scrollback, in order
//! ([`block`]). A run of lines that no frame carried becomes one dim line
//! that says how many were skipped. Each line goes up once: the client
//! counts what its scrollback got, and a line that came twice (in two
//! frames from one base) is written the first time only.

use std::collections::{BTreeMap, VecDeque};

/// The most bytes of lines in one frame: under a flood at 64 KiB/s a
/// frame's lines then wait at most a quarter of a second in the link.
pub const BYTES_MOST: usize = 16 << 10;
/// The longest line kept: a row longer than it (colours in each cell of a
/// wide screen) is cut there.
pub const LINE_MOST: usize = 4 << 10;
/// The most lines that the client keeps for its next draw; the oldest
/// beyond it are said as skipped.
pub const PENDING_MOST: usize = 1000;

/// The far end's: the count of the lines that left the top of the primary
/// screen, and the newest kept of them, each with its place in the count
/// and as a row of text with its colours.
#[derive(Debug, Default)]
pub struct Lines {
    total: u64,
    held: VecDeque<(u64, String)>,
    /// The most kept: the screen's rows; 0 for a model with no lines,
    /// which counts none either (version 1, and a model of the client).
    keep: usize,
    /// A new size moves rows off the screen: the client's terminal moves
    /// its own, so those are not counted.
    paused: bool,
    /// The rows that leave now are kept, not only counted.
    keeping: bool,
}

impl Lines {
    /// Lines that keep the newest `keep`.
    pub fn new(keep: usize) -> Lines {
        Lines { keep, keeping: true, ..Lines::default() }
    }

    /// The most kept.
    pub fn keep(&self) -> usize {
        self.keep
    }

    /// While not `keeping`, the rows that leave the screen are counted and
    /// not kept: they cannot be the newest.
    pub fn keeping(&mut self, keeping: bool) {
        self.keeping = keeping;
    }

    /// The count of the lines that left the top, since the start.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Keep the newest `keep` from now on, for a new size; a model with no
    /// lines keeps none still.
    pub fn set_keep(&mut self, keep: usize) {
        if self.keep == 0 {
            return;
        }
        self.keep = keep.max(1);
        while self.held.len() > keep {
            self.held.pop_front();
        }
    }

    /// While `paused`, rows that leave the screen are not lines.
    pub fn pause(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// A row left the top of the primary screen.
    pub fn push(&mut self, row: &vt100::capture::RowContents<'_>) {
        if self.paused || self.keep == 0 {
            return;
        }
        self.total += 1;
        if !self.keeping {
            return;
        }
        // The oldest line's room is the newest one's: no allocation once
        // the ring is full.
        let reused = if self.held.len() >= self.keep { self.held.pop_front() } else { None };
        let mut line = reused.map(|(_, line)| line).unwrap_or_default();
        line.clear();
        let mut state = vt100::capture::BasicFormattedCaptureState::new();
        let _ = row.write_formatted_basic(&mut line, &mut state);
        cut(&mut line, LINE_MOST - 3);
        // A row ends with its colours: the next one starts plain.
        if line.contains('\x1b') {
            line.push_str("\x1b[m");
        }
        self.held.push_back((self.total, line));
    }

    /// The lines after the line `since` that a frame carries: the newest,
    /// in an unbroken run that ends at the count, at most one screen of
    /// them and [`BYTES_MOST`] together, the oldest first. A line that was
    /// counted and not kept ends the run; the lines before it are said
    /// skipped at the client.
    pub fn after(&self, since: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let (mut want, mut bytes) = (self.total, 0);
        for (index, line) in self.held.iter().rev() {
            if *index != want || *index <= since || out.len() >= self.keep || bytes + line.len() > BYTES_MOST {
                break;
            }
            bytes += line.len();
            out.push(line.as_bytes().to_vec());
            want -= 1;
        }
        out.reverse();
        out
    }
}

/// Where the last part of `bytes` that holds `lines` line feeds (LF, VT
/// and FF, which a terminal takes alike) starts; 0 where all of `bytes`
/// holds fewer. Only the rows that leave the screen in that part can be the
/// newest `lines` of the write; the rows before it are counted alone. A
/// write whose last rows leave by another way (a long line that wraps, a
/// scroll by `CSI S`) keeps them too, as they are in that part.
pub fn tail(bytes: &[u8], lines: usize) -> usize {
    let mut seen = 0;
    for (at, byte) in bytes.iter().enumerate().rev() {
        if matches!(byte, b'\n' | 0x0b | 0x0c) {
            seen += 1;
            if seen > lines {
                return at + 1;
            }
        }
    }
    0
}

/// `line` cut to at most `most` bytes, at the start of a character.
fn cut(line: &mut String, most: usize) {
    if line.len() <= most {
        return;
    }
    let mut at = most;
    while !line.is_char_boundary(at) {
        at -= 1;
    }
    line.truncate(at);
}

/// The client's: the lines that came with frames, which its terminal's
/// scrollback did not get yet.
#[derive(Debug, Default)]
pub struct Pending {
    /// The count of lines that the scrollback got or that were said
    /// skipped: the far end's count at the last draw.
    written: u64,
    lines: BTreeMap<u64, Vec<u8>>,
}

impl Pending {
    /// The lines of a frame whose state's count is `total`: the lines
    /// `total - lines.len() + 1` to `total`. A line that the scrollback got
    /// is passed over.
    pub fn insert(&mut self, total: u64, lines: Vec<Vec<u8>>) {
        // A count at the end of `u64` comes from no far end; it saturates.
        let first = total.saturating_add(1).saturating_sub(lines.len() as u64);
        for (n, line) in lines.into_iter().enumerate() {
            let index = first.saturating_add(n as u64);
            if index > self.written {
                self.lines.insert(index, line);
            }
        }
        while self.lines.len() > PENDING_MOST {
            self.lines.pop_first();
        }
    }

    /// The rows that the scrollback takes to reach the count `total`: each
    /// line held after the last draw, in order, and in each gap one line
    /// that says how many were skipped, at most `cols` wide. Nothing where
    /// `total` is not past the last draw (version 1 says no count).
    pub fn take(&mut self, total: u64, cols: u16) -> Vec<Vec<u8>> {
        if total <= self.written {
            return Vec::new();
        }
        let later = self.lines.split_off(&total.saturating_add(1));
        let taken = std::mem::replace(&mut self.lines, later);
        let mut out = Vec::new();
        let mut next = self.written + 1;
        for (index, line) in taken {
            if index > next {
                out.push(skipped(index - next, cols));
            }
            out.push(clean(&line));
            next = index.saturating_add(1);
        }
        if next <= total {
            out.push(skipped(total - next + 1, cols));
        }
        self.written = total;
        out
    }

    /// The count of lines that the scrollback got or that were said
    /// skipped.
    pub fn written(&self) -> u64 {
        self.written
    }
}

/// The dim line in place of `count` lines that no frame carried, cut to
/// `cols` (its text is ASCII: a byte is a column).
fn skipped(count: u64, cols: u16) -> Vec<u8> {
    let noun = if count == 1 { "line" } else { "lines" };
    let mut text = format!("[podssh: {count} {noun} skipped]");
    text.truncate(usize::from(cols.max(1)));
    format!("\x1b[2m{text}\x1b[m").into_bytes()
}

/// `line` with no control character but the SGR sequences of its colours
/// (`ESC [`, digits, `;` or `:`, then `m`): a line of the far end never
/// moves the cursor out of its row. Each other sequence of `ESC [` goes
/// whole, its final byte too; another `ESC` goes alone.
pub fn clean(line: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(line);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            if !c.is_control() {
                out.push(c);
            }
            continue;
        }
        if chars.next_if_eq(&'[').is_none() {
            continue;
        }
        // The parameters and the intermediates, then the final byte.
        let mut sequence = String::from("\x1b[");
        while let Some(p) = chars.next_if(|p| ('\x20'..='\x3f').contains(p)) {
            sequence.push(p);
        }
        let colours = sequence[2..].chars().all(|p| p.is_ascii_digit() || p == ';' || p == ':');
        match chars.next_if(|f| ('\x40'..='\x7e').contains(f)) {
            Some('m') if colours => {
                sequence.push('m');
                out.push_str(&sequence);
            }
            _ => {}
        }
    }
    out.into_bytes()
}

/// What moves `rows` into the scrollback of a terminal of `height` rows:
/// for each screen of them, each row written at the top, one under the
/// other, then as many line feeds from the last row (`999`, which a
/// terminal takes as its last, whatever its size). The cursor is hidden
/// while it moves; the draw that follows shows it where the state has it.
/// After it, the screen's content is the old one moved up, and the cursor
/// is on the last row.
pub fn block(rows: &[Vec<u8>], height: u16) -> Vec<u8> {
    let mut out = b"\x1b[?25l".to_vec();
    for chunk in rows.chunks(usize::from(height.max(1))) {
        for (row, line) in (1u32..).zip(chunk) {
            out.extend_from_slice(format!("\x1b[m\x1b[{row};1H\x1b[2K").as_bytes());
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b"\x1b[m\x1b[999;1H");
        out.extend(std::iter::repeat_n(b'\n', chunk.len()));
    }
    out
}

#[cfg(test)]
#[path = "scroll_tests.rs"]
mod tests;

// The rule of the lines as a property, at the sender's own pace (T-1056).
#[cfg(test)]
#[path = "gap_tests.rs"]
mod gap_tests;
