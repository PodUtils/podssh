//! What a client whose terminal holds none of a kept shell's screen gets at
//! an attach (T-161), beside the bytes of the ring: the modes that the
//! program set before the replay's first byte, then a redraw.
//!
//! A client that gives its offset (`count@podssh`, T-833) has each byte up
//! to it, so its terminal holds the screen and its modes: it gets the bytes
//! alone. Each other attach may come from a new process on another host,
//! whose terminal is empty, and its replay (from the detach, or from the
//! ring's first boundary after a reset) can start long after a full-screen
//! program set the alternate screen and its keys. So the modes in effect at
//! the replay's start go first, read by `pod-term` from the bytes that the
//! ring dropped too; and once the channel has the shell, a change of the
//! pty's size and its return make the program draw its screen again.

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

/// Whether an attach gets the modes and a redraw: each one but a replay
/// from a count that the ring held, which is byte-exact (T-833).
pub(super) fn fresh(counted: bool, reset: bool) -> bool {
    reset || !counted
}

/// The bytes that put a terminal in any state into the modes in effect
/// before the offset `at` of the shell's output (the alternate screen, the
/// keys of the cursor and the keypad, bracketed paste, the mouse); none
/// where the ring cannot say.
pub(super) fn modes_before(ring: &Ring, at: u64) -> Vec<u8> {
    ring.modes_at(at.min(ring.end())).map(|modes| modes.restore()).unwrap_or_default()
}

/// The size of the redraw's first half: a row less, or one more on a pty
/// of one row. Rows, not columns: a line editor at its prompt redraws its
/// line in place, where a new width can make it wrap the line again.
pub(super) fn nudged(size: Size) -> Size {
    let rows = if size.rows > 1 { size.rows - 1 } else { size.rows + 1 };
    Size { rows, ..size }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::time::Instant;

    use super::*;

    /// One rule for each attach: a count that the ring held is exact, and
    /// each other attach (none, or a reset, asked or chosen) is fresh.
    #[test]
    fn only_an_attach_from_a_held_count_skips_the_modes_and_the_redraw() {
        let cases = [((true, false), false), ((false, false), true), ((true, true), true), ((false, true), true)];
        for ((counted, reset), want) in cases {
            assert_eq!(fresh(counted, reset), want, "counted {counted}, reset {reset}");
        }
    }

    #[test]
    fn the_nudge_changes_the_rows_alone() {
        let size = |cols, rows| Size { cols, rows, px_width: 640, px_height: 480 };
        for (from, to) in [(size(80, 24), size(80, 23)), (size(80, 1), size(80, 2)), (size(1, 2), size(1, 1))] {
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
    /// where the kept bytes turn one off again.
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
    }
}
