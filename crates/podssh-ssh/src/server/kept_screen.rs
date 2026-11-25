//! What a client whose terminal holds none of a kept shell's screen gets at
//! an attach (T-161), beside the bytes of the ring: the modes that the
//! program set before the replay's first byte, then a redraw.
//!
//! A client that gives its offset (`count@podssh`, T-833) is served the
//! bytes alone, byte for byte. Each other attach may come from a new process
//! on another host, whose terminal is empty, and its replay (from the
//! detach, or from the ring's first boundary after a reset) can start long
//! after a full-screen program set the alternate screen and its keys. So
//! the modes in effect at the replay's start go first, read by `pod-term`
//! from the bytes that the ring dropped too; and once the channel has the
//! shell, a change of the pty's size and its return make the program draw
//! its screen again.

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever kept there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::time::Duration;

use pod_term::grammar::Ring;

use crate::terminal::Size;

/// How long the pty keeps the nudged size before its own comes back: time
/// for the program to read the first change, so that one that redraws
/// only when its size differs sees two changes, not one that undid itself.
pub(super) const REDRAW_PAUSE: Duration = Duration::from_millis(100);

/// Whether an attach gets the modes before its bytes: each one but a
/// replay from a count that the ring held (`reset` is false then), which
/// T-833 serves byte for byte; the client counts its stdout, so modes there
/// would move its count. Each attach gets the redraw (`kept_catch.rs`).
pub(super) fn fresh(counted: bool, reset: bool) -> bool {
    reset || !counted
}

/// The bytes that put a terminal in any state into the modes in effect
/// before the offset `at` of the shell's output (the alternate screen, the
/// keys of the cursor and the keypad, bracketed paste, the mouse); none
/// where the ring holds no boundary to read them from.
pub(super) fn modes_before(ring: &Ring, at: u64) -> Vec<u8> {
    ring.modes_at(at.min(ring.end())).map(|modes| modes.restore()).unwrap_or_default()
}

/// The rows that a fresh attach's tail gives where the pty's size is not
/// known: a terminal's usual height.
pub(super) const TAIL_ROWS: u32 = 24;

/// Where a fresh attach (no count, no reset) starts, where that gives more
/// than the bytes since the detach (`base`): at the first boundary of the
/// grammar on or after the start of the ring's last `rows` lines, so that a
/// shell at a still prompt, which draws nothing again at a change of size
/// (T-161's measure), shows its screen (T-901). None where the program is
/// on the alternate screen (its redraw gives the screen), where the ring
/// holds no boundary, or where the tail starts at the detach or after it.
pub(super) fn tail_from(ring: &Ring, base: u64, rows: u32) -> Option<u64> {
    let start = ring.start()?;
    if ring.modes_at(ring.end()).is_none_or(|modes| modes.alternate()) {
        return None;
    }
    let kept = ring.kept();
    // The byte after the newline that ends the line before the last `rows`:
    // the screen holds `rows` lines, the last of them the prompt.
    let rows = usize::try_from(rows.max(1)).unwrap_or(usize::MAX);
    let mut seen = 0;
    let mut line_start = 0;
    for (at, byte) in kept.iter().enumerate().rev() {
        if *byte == b'\n' && at + 1 < kept.len() {
            seen += 1;
            if seen == rows {
                line_start = at + 1;
                break;
            }
        }
    }
    let mut tracker = pod_term::grammar::Tracker::new();
    let mut first = None;
    let target = line_start as u64;
    tracker.feed(&kept, std::time::Instant::now(), |boundary| {
        if first.is_none() && boundary.at >= target {
            first = Some(boundary.at);
        }
    });
    // A tail that ends in the middle of a sequence starts nowhere clean.
    let tail = start + if line_start == 0 { 0 } else { first? };
    (tail < base).then_some(tail)
}

/// The size of the redraw's first half: a row less, or one more on a pty
/// of one row. Rows, not columns: a line editor at its prompt redraws its
/// line in place, where a new width can make it wrap the line again. The
/// rows are cut to what the kernel holds first, so the nudge is a change
/// there too.
pub(super) fn nudged(size: Size) -> Size {
    let rows = size.rows.min(u32::from(u16::MAX));
    let rows = if rows > 1 { rows - 1 } else { rows + 1 };
    Size { rows, ..size }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::time::Instant;

    use super::*;

    /// The tail of a fresh attach, one rule: the start of the last `rows`
    /// lines at a boundary, only before the detach, never on the alternate
    /// screen; the whole ring where it holds fewer lines.
    #[test]
    fn a_fresh_attach_gets_the_last_rows_before_the_detach_outside_the_alternate_screen() {
        let lines = b"one\r\ntwo\r\nthree\r\n$ ";
        let at = |text: &[u8], needle: &[u8]| text.windows(needle.len()).position(|w| w == needle).unwrap() as u64;
        let ring_of = |parts: &[&[u8]]| {
            let mut ring = Ring::new(4096);
            for part in parts {
                ring.push(part, Instant::now());
            }
            ring
        };
        let plain = ring_of(&[lines]);
        let end = plain.end();
        let cases: &[(&Ring, u64, u32, Option<u64>)] = &[
            (&plain, end, 2, Some(at(lines, b"three"))),
            (&plain, end, 3, Some(at(lines, b"two"))),
            (&plain, end, 24, Some(0)),
            // Output came since the detach: the tail still starts before it.
            (&plain, at(lines, b"$ "), 2, Some(at(lines, b"three"))),
            // The tail starts at the detach or after it: the replay holds it.
            (&plain, at(lines, b"three"), 2, None),
            (&plain, 0, 24, None),
        ];
        for (ring, base, rows, want) in cases {
            assert_eq!(tail_from(ring, *base, *rows), *want, "base {base}, rows {rows}");
        }
        let alternate = ring_of(&[lines, b"\x1b[?1049h", b"a screen"]);
        assert_eq!(tail_from(&alternate, alternate.end(), 2), None, "on the alternate screen");
        let left = ring_of(&[b"\x1b[?1049h", b"a screen", b"\x1b[?1049l", lines]);
        assert!(tail_from(&left, left.end(), 2).is_some(), "the alternate screen left");
        assert_eq!(tail_from(&Ring::new(64), 0, 24), None, "an empty ring");
    }

    /// The nudge changes the rows alone, by one, as the kernel holds them.
    #[test]
    fn the_nudge_changes_the_rows_alone() {
        let size = |cols, rows| Size { cols, rows, px_width: 640, px_height: 480 };
        let cases = [
            (size(80, 24), size(80, 23)),
            (size(80, 1), size(80, 2)),
            (size(80, 0), size(80, 1)),
            (size(1, 2), size(1, 1)),
            (size(80, u32::MAX), size(80, u32::from(u16::MAX) - 1)),
        ];
        for (from, to) in cases {
            assert_eq!(nudged(from), to, "{from:?}");
        }
    }

    /// A model terminal that reads `bytes` from its start.
    fn screen(bytes: &[u8]) -> vt100::Parser {
        let mut parser = vt100::Parser::new(NonZeroU16::new(24).unwrap(), NonZeroU16::new(80).unwrap(), 0);
        parser.process(bytes);
        parser
    }

    /// The modes that a model shows: the alternate screen, the cursor keys,
    /// the keypad and bracketed paste.
    fn modes(parser: &vt100::Parser) -> [bool; 4] {
        let s = parser.screen();
        [s.alternate_screen(), s.application_cursor(), s.application_keypad(), s.bracketed_paste()]
    }

    /// A ring that dropped the bytes that set the modes: its bytes alone
    /// leave a new terminal with none of them; the modes before its start,
    /// then its bytes, give the modes of a terminal that read it all, also
    /// where the kept bytes turn one off again. A ring with no boundary
    /// gives no modes.
    #[test]
    fn the_modes_before_a_cut_ring_bring_a_new_terminal_to_the_whole_streams() {
        let set = b"\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h";
        let text = b"a line of text that the ring drops\r\n".repeat(8);
        let tails: [&[u8]; 3] = [b"", b"\x1b[?2004l", b"\x1b>\x1b[?1l"];
        for tail in tails {
            let mut ring = Ring::new(128);
            let now = Instant::now();
            ring.push(set, now);
            ring.push(&text, now);
            ring.push(tail, now);
            let start = ring.start().expect("text ends at a boundary");
            assert!(start > set.len() as u64, "the ring dropped the modes");
            let whole = screen(&[&set[..], &text[..], tail].concat());
            assert_ne!(modes(&screen(&ring.kept())), modes(&whole), "{tail:?}: the bytes alone");
            let restored = screen(&[modes_before(&ring, start), ring.kept()].concat());
            assert_eq!(modes(&restored), modes(&whole), "{tail:?}");
        }
        assert!(modes_before(&Ring::new(128), 0).is_empty(), "an empty ring");
    }
}
