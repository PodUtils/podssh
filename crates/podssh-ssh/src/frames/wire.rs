//! The frames of the far end's screen on the wire (T-303). `podssh ssh
//! --frames` asks with `env frames@podssh v1` and a reply, on a channel with
//! a pty, before the shell or the command; a server that does not know the
//! request answers FAILURE, and the session carries each byte, as before.
//! `podssh serve` then sends no data on the channel: each frame is a record
//! in extended data of a code of podssh's own, and the client acknowledges
//! with `env frames-ack@podssh NUMBER`, which asks for no reply.
//!
//! A frame is [`HEADER`] bytes and its body. The header: the version (1);
//! the flags (bit 0: the body draws the whole screen from an empty one; bit
//! 1: the far end rang its bell; bit 2: the last frame, the program's output
//! ended; each other bit 0); the number of the frame's state and the number
//! of the state that the body starts from (0 with bit 0), each a big-endian
//! `u64`; the rows and the columns, each a big-endian `u16`; and the length
//! of the body, a big-endian `u32`. The body is terminal output that turns a
//! model of the base state into the frame's state.

/// The `env` request that asks the far end for frames.
pub const ENV: &str = "frames@podssh";
/// The one value of [`ENV`]: the version of the frames below.
pub const VERSION: &str = "v1";
/// The `env` request that acknowledges frames: its value is [`Ack::value`].
pub const ACK: &str = "frames-ack@podssh";
/// The code of the extended data: in the range that RFC 4250 leaves for
/// private use (0xFE000000 to 0xFFFFFFFF, section 4.4.3), "POF" after 0xFE.
pub const EXT: u32 = 0xFE50_4F46;
/// The length of a frame's header.
pub const HEADER: usize = 26;
/// The longest body: a screen of 500 by 200 whose every cell has colours of
/// its own stays under it; a length above it is no frame of this version.
pub const MAX_BODY: usize = 8 << 20;

const FIRST: u8 = 1;
const FULL: u8 = 1;
const BELL: u8 = 2;
const LAST: u8 = 4;

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
}

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub head: Head,
    pub body: Vec<u8>,
}

/// The bytes of a frame of `head` and `body`. A body longer than
/// [`MAX_BODY`] is cut there: the receiver then draws a part, and the next
/// frame repairs it; the sender never makes one (a screen is far smaller).
pub fn encode(head: Head, body: &[u8]) -> Vec<u8> {
    let body = &body[..body.len().min(MAX_BODY)];
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.push(FIRST);
    let flag = |on: bool, bit: u8| if on { bit } else { 0 };
    out.push(flag(head.full, FULL) | flag(head.bell, BELL) | flag(head.last, LAST));
    out.extend_from_slice(&head.number.to_be_bytes());
    out.extend_from_slice(&head.base.to_be_bytes());
    out.extend_from_slice(&head.rows.to_be_bytes());
    out.extend_from_slice(&head.cols.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The header at the start of `bytes`, and the length of its body. `Err`
/// for bytes that are no header of this version.
fn head_of(bytes: &[u8; HEADER]) -> Result<(Head, usize), String> {
    let (first, flags) = (bytes[0], bytes[1]);
    if first != FIRST || flags & !(FULL | BELL | LAST) != 0 {
        return Err(format!("a frame that this version cannot read ({first:#04x} {flags:#04x})"));
    }
    let wide = |at: usize| {
        let mut part = [0u8; 8];
        part.copy_from_slice(&bytes[at..at + 8]);
        u64::from_be_bytes(part)
    };
    let short = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let length = u32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]) as usize;
    let head = Head {
        full: flags & FULL != 0,
        bell: flags & BELL != 0,
        last: flags & LAST != 0,
        number: wide(2),
        base: wide(10),
        rows: short(18),
        cols: short(20),
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
    Ok((head, length))
}

/// The frames of a stream of extended data, which SSH may cut anywhere.
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
        while self.part.len() - at >= HEADER {
            let mut header = [0u8; HEADER];
            header.copy_from_slice(&self.part[at..at + HEADER]);
            let (head, length) = head_of(&header)?;
            let end = at + HEADER + length;
            if self.part.len() < end {
                break;
            }
            out.push(Frame { head, body: self.part[at + HEADER..end].to_vec() });
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
mod tests {
    use super::*;

    fn head(number: u64, base: u64) -> Head {
        Head { full: base == 0, bell: false, last: false, number, base, rows: 24, cols: 80 }
    }

    /// Each frame reads back the same, however SSH cuts the stream.
    #[test]
    fn a_frame_reads_back_across_any_cut() {
        let sent = vec![
            Frame { head: head(1, 0), body: b"\x1b[H\x1b[Jone".to_vec() },
            Frame { head: Head { bell: true, ..head(2, 1) }, body: Vec::new() },
            Frame { head: Head { rows: 60, cols: 200, ..head(u64::MAX, 7) }, body: vec![b'x'; 3000] },
            Frame { head: Head { last: true, ..head(9, 0) }, body: "caf\u{e9} \u{4e16}".as_bytes().to_vec() },
        ];
        let stream: Vec<u8> = sent.iter().flat_map(|f| encode(f.head, &f.body)).collect();
        for cut in [1, 2, 7, HEADER - 1, HEADER, HEADER + 1, 1000, stream.len()] {
            let mut decoder = Decoder::default();
            let got: Vec<Frame> = stream.chunks(cut).flat_map(|c| decoder.feed(c).unwrap()).collect();
            assert_eq!(got, sent, "cut every {cut} bytes");
            assert!(decoder.part.is_empty(), "nothing is left after the last frame (cut {cut})");
        }
    }

    /// A header that is no frame of this version is refused, each field by
    /// one rule: the place of the byte, its value, and the word of the
    /// refusal.
    #[test]
    fn a_header_of_another_version_or_with_no_state_is_refused() {
        let good = encode(head(5, 4), b"body");
        assert_eq!(Decoder::default().feed(&good).unwrap().len(), 1);
        let cases: &[(&str, usize, u8, &str)] = &[
            ("another version", 0, 2, "cannot read"),
            ("a flag that this version does not have", 1, 8, "cannot read"),
            ("the number 0", 9, 0, "no state"),
            ("a base that is not before the number", 17, 5, "no state"),
            ("a whole screen with a base", 1, FULL, "no state"),
            ("no rows", 19, 0, "no state"),
            ("no columns", 21, 0, "no state"),
            ("a body above the most", 22, 0xff, "above the most"),
        ];
        for (what, at, value, word) in cases {
            let mut bad = good.clone();
            bad[*at] = *value;
            let refused = Decoder::default().feed(&bad).expect_err(what);
            assert!(refused.contains(word), "{what}: {refused}");
        }
    }

    /// A body above the most is cut by the sender, so its frame still reads.
    #[test]
    fn a_body_above_the_most_is_cut_at_the_most() {
        let bytes = encode(head(1, 0), &vec![b'a'; MAX_BODY + 9]);
        assert_eq!(bytes.len(), HEADER + MAX_BODY);
        let frames = Decoder::default().feed(&bytes).unwrap();
        assert_eq!(frames[0].body.len(), MAX_BODY);
    }

    /// An acknowledgement reads back; another text is none.
    #[test]
    fn an_acknowledgement_reads_back_and_another_text_is_none() {
        for ack in [
            Ack { number: 0, lost: false },
            Ack { number: 41, lost: false },
            Ack { number: 41, lost: true },
            Ack { number: u64::MAX, lost: true },
        ] {
            assert_eq!(Ack::parse(&ack.value()), Some(ack), "{}", ack.value());
        }
        for bad in ["", " lost", "+4", "-1", "4 ", "4 lost ", "4  lost", "0x10", "18446744073709551616", "4\n", "v1"] {
            assert_eq!(Ack::parse(bad), None, "{bad:?}");
        }
    }
}
