//! The frames of the far end's screen on the wire (T-303). `podssh ssh
//! --frames` asks with `env frames@podssh v1` and a reply; `--frames-scroll`
//! asks with `env frames@podssh v2` and a reply, then at once with
//! `env frames@podssh v1` and a reply, on a channel with a pty, before the
//! shell or the command. The replies come in order: a far end that takes
//! `v2` refuses the second ask, and one that knows only `v1` (an older
//! podssh serve) refuses the first and takes the second. A server that does
//! not know the request refuses both, and the session carries each byte,
//! as before. `podssh serve` then sends no data on the channel: each frame
//! is a record in extended data of a code of podssh's own, and the client
//! acknowledges with `env frames-ack@podssh NUMBER`, which asks for no
//! reply.
//!
//! A frame is a header and its body. The header of version 1, [`HEADER_V1`]
//! bytes: the version (1); the flags (bit 0: the body draws the whole
//! screen from an empty one; bit 1: the far end rang its bell; bit 2: the
//! last frame, the program's output ended; each other bit 0); the number of
//! the frame's state and the number of the state that the body starts from
//! (0 with bit 0), each a big-endian `u64`; the rows and the columns, each a
//! big-endian `u16`; and the length of the body, a big-endian `u32`. The
//! body is terminal output that turns a model of the base state into the
//! frame's state.
//!
//! Version 2, [`HEADER`] bytes, adds the lines that left the top of the
//! screen, so that the client's terminal keeps them in its scrollback: after
//! the length, the count of lines that left the top of the far end's screen
//! since its start, up to this state (a big-endian `u64`); and the flag bit
//! 3, with which the body starts with those lines: their count (a
//! big-endian `u16`), then each line as its length (a big-endian `u16`)
//! and its text, a row with no control byte but the SGR sequences of its
//! colours. The lines are the last ones before the state: with `n` of them
//! and the count `t`, they are the lines `t - n + 1` to `t`. The length of
//! the header counts the lines and the screen's body together.

/// The `env` request that asks the far end for frames.
pub const ENV: &str = "frames@podssh";
/// The value of [`ENV`] that this build asks first: the newest version.
pub const VERSION: &str = "v2";
/// The `env` request that acknowledges frames: its value is [`Ack::value`].
pub const ACK: &str = "frames-ack@podssh";
/// The code of the extended data: in the range that RFC 4250 leaves for
/// private use (0xFE000000 to 0xFFFFFFFF, section 4.4.3), "POF" after 0xFE.
pub const EXT: u32 = 0xFE50_4F46;
/// The length of a frame's header, version 2.
pub const HEADER: usize = 34;
/// The length of a frame's header, version 1.
pub const HEADER_V1: usize = 26;
/// The longest body: a screen of 500 by 200 whose every cell has colours of
/// its own stays under it; a length above it is no frame of this version.
pub const MAX_BODY: usize = 8 << 20;

const FULL: u8 = 1;
const BELL: u8 = 2;
const LAST: u8 = 4;
const LINES: u8 = 8;

/// A version of the frames: what a far end sends on a channel, as the
/// client asked and the far end took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// The screen alone.
    One,
    /// The screen, and the lines that left its top.
    Two,
}

impl Version {
    /// The versions that a client asks for, the newest first.
    pub const ASKED: [Version; 2] = [Version::Two, Version::One];

    /// The value of [`ENV`] that asks for this version.
    pub fn word(self) -> &'static str {
        match self {
            Version::One => "v1",
            Version::Two => "v2",
        }
    }

    /// The version that `word` asks for; `None` for a version that this
    /// build does not send.
    pub fn of(word: &str) -> Option<Version> {
        Version::ASKED.into_iter().find(|version| version.word() == word)
    }

    fn byte(self) -> u8 {
        match self {
            Version::One => 1,
            Version::Two => 2,
        }
    }

    fn header(self) -> usize {
        match self {
            Version::One => HEADER_V1,
            Version::Two => HEADER,
        }
    }
}

/// The header of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The body draws the whole screen, from no base.
    pub full: bool,
    /// The far end rang its bell since the frame before.
    pub bell: bool,
    /// The program's output ended: no frame follows.
    pub last: bool,
    /// The number of the state that the frame gives, from 1.
    pub number: u64,
    /// The number of the state that the body starts from; 0 with `full`.
    pub base: u64,
    pub rows: u16,
    pub cols: u16,
    /// The count of lines that left the top of the far end's screen, up to
    /// this state; 0 in version 1, which does not say it.
    pub total: u64,
}

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub head: Head,
    /// The last lines that left the top of the screen, the oldest first:
    /// the lines `head.total - lines.len() + 1` to `head.total`.
    pub lines: Vec<Vec<u8>>,
    pub body: Vec<u8>,
}

/// The bytes of a frame of `version`, `head`, `lines` and `body`. Version 1
/// carries no line. Of `lines`, at most the last `head.total` go, each cut
/// to the most that its length can say. A body longer than [`MAX_BODY`]
/// with its lines is cut there: the receiver then draws a part, and the
/// next frame repairs it; the sender never makes one (a screen is far
/// smaller).
pub fn encode(version: Version, head: Head, lines: &[Vec<u8>], body: &[u8]) -> Vec<u8> {
    let most = usize::try_from(head.total).unwrap_or(usize::MAX).min(usize::from(u16::MAX));
    let lines = match version {
        Version::One => &lines[..0],
        Version::Two => &lines[lines.len().saturating_sub(most)..],
    };
    let mut rest = Vec::new();
    if !lines.is_empty() {
        rest.extend_from_slice(&(lines.len() as u16).to_be_bytes());
        for line in lines {
            let line = &line[..line.len().min(usize::from(u16::MAX))];
            rest.extend_from_slice(&(line.len() as u16).to_be_bytes());
            rest.extend_from_slice(line);
        }
    }
    rest.extend_from_slice(body);
    rest.truncate(MAX_BODY);
    let mut out = Vec::with_capacity(version.header() + rest.len());
    out.push(version.byte());
    let flag = |on: bool, bit: u8| if on { bit } else { 0 };
    out.push(flag(head.full, FULL) | flag(head.bell, BELL) | flag(head.last, LAST) | flag(!lines.is_empty(), LINES));
    out.extend_from_slice(&head.number.to_be_bytes());
    out.extend_from_slice(&head.base.to_be_bytes());
    out.extend_from_slice(&head.rows.to_be_bytes());
    out.extend_from_slice(&head.cols.to_be_bytes());
    out.extend_from_slice(&(rest.len() as u32).to_be_bytes());
    if version == Version::Two {
        out.extend_from_slice(&head.total.to_be_bytes());
    }
    out.extend_from_slice(&rest);
    out
}

fn wide(bytes: &[u8], at: usize) -> u64 {
    let mut part = [0u8; 8];
    part.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(part)
}

fn short(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// The version that a frame starting with `first` has. `Err` for a byte
/// that is no version of this build.
fn version_of(first: u8) -> Result<Version, String> {
    match first {
        1 => Ok(Version::One),
        2 => Ok(Version::Two),
        _ => Err(format!("a frame that this version cannot read ({first:#04x})")),
    }
}

/// The header in `bytes` (the length of `version`'s header), the length of
/// its body, and whether the body starts with lines. `Err` for bytes that
/// are no header of `version`.
fn head_of(version: Version, bytes: &[u8]) -> Result<(Head, usize, bool), String> {
    let flags = bytes[1];
    let known = match version {
        Version::One => FULL | BELL | LAST,
        Version::Two => FULL | BELL | LAST | LINES,
    };
    if flags & !known != 0 {
        return Err(format!("a frame that this version cannot read ({:#04x} {flags:#04x})", bytes[0]));
    }
    let length = u32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]) as usize;
    let head = Head {
        full: flags & FULL != 0,
        bell: flags & BELL != 0,
        last: flags & LAST != 0,
        number: wide(bytes, 2),
        base: wide(bytes, 10),
        rows: short(bytes, 18),
        cols: short(bytes, 20),
        total: if version == Version::Two { wide(bytes, 26) } else { 0 },
    };
    // A state has a number from 1, a size, and a base that came before it.
    let numbered = head.number > 0 && if head.full { head.base == 0 } else { head.base < head.number };
    if !numbered || head.rows == 0 || head.cols == 0 {
        return Err(format!(
            "a frame with no state (number {}, base {}, {} by {})",
            head.number, head.base, head.cols, head.rows
        ));
    }
    if length > MAX_BODY {
        return Err(format!("a frame of {length} bytes, above the most of {MAX_BODY}"));
    }
    Ok((head, length, flags & LINES != 0))
}

/// The lines at the start of `rest`, and the screen's body after them.
/// `Err` for lines that overrun the body, or that are more than left the
/// screen (`total`).
fn lines_of(rest: &[u8], total: u64) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    let overrun = || "a frame whose lines overrun its body".to_string();
    let count = usize::from(short(rest.get(..2).ok_or_else(overrun)?, 0));
    if count == 0 || count as u64 > total {
        return Err(format!("a frame of {count} lines, where {total} left its screen"));
    }
    let (mut lines, mut at) = (Vec::with_capacity(count), 2);
    for _ in 0..count {
        let length = usize::from(short(rest.get(at..at + 2).ok_or_else(overrun)?, 0));
        lines.push(rest.get(at + 2..at + 2 + length).ok_or_else(overrun)?.to_vec());
        at += 2 + length;
    }
    Ok((lines, rest[at..].to_vec()))
}

/// The frames of a stream of extended data, which SSH may cut anywhere.
/// Each frame says its version, so frames of both versions read.
#[derive(Debug, Default)]
pub struct Decoder {
    part: Vec<u8>,
}

impl Decoder {
    /// The frames that `bytes` complete. `Err` for bytes that are no frame
    /// of this version: nothing after them can be read, as the stream has
    /// no other mark of a frame's start.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, String> {
        self.part.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(first) = self.part.get(at) {
            let version = version_of(*first)?;
            let size = version.header();
            if self.part.len() - at < size {
                break;
            }
            let (head, length, lined) = head_of(version, &self.part[at..at + size])?;
            let end = at + size + length;
            if self.part.len() < end {
                break;
            }
            let rest = &self.part[at + size..end];
            let (lines, body) = if lined { lines_of(rest, head.total)? } else { (Vec::new(), rest.to_vec()) };
            out.push(Frame { head, lines, body });
            at = end;
        }
        self.part.drain(..at);
        Ok(out)
    }
}

/// The client's word after frames came: the number of the newest state
/// that it holds, and whether the last frame had a base that it does not
/// hold, so that the next frame must draw the whole screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub number: u64,
    pub lost: bool,
}

impl Ack {
    /// The value of [`ACK`]: the number in decimal, then ` lost` where the
    /// base was not held.
    pub fn value(self) -> String {
        if self.lost {
            format!("{} lost", self.number)
        } else {
            self.number.to_string()
        }
    }

    /// The acknowledgement of `value`; `None` for another text, which the
    /// far end passes over.
    pub fn parse(value: &str) -> Option<Ack> {
        let (number, lost) = match value.strip_suffix(" lost") {
            Some(number) => (number, true),
            None => (value, false),
        };
        // Digits alone: `u64`'s own reading takes a sign too.
        if number.is_empty() || number.len() > 20 || !number.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        number.parse().ok().map(|number| Ack { number, lost })
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
