//! Where the replay of a kept shell's output starts (T-159, T-833), apart
//! from `kept.rs` so that each file stays short: the bytes of the ring from
//! an offset, and the choice of replay or reset.
//!
//! The offsets count the shell's output from its start. A client that has
//! the output up to an offset in the ring gets the rest from there; one
//! whose offset the ring no longer holds, or that is past the output, or
//! that asks, gets a reset: the ring from its first boundary of the grammar
//! (T-221), after a line that says so, with the offset where it starts. serve
//! decides the reset itself, so a gap that cannot be served never repeats
//! (the gap of EternalTerminal that T-833 read).

use pod_term::grammar::Ring;

// The lines of a reset and of a dropped part, which the client reads to
// keep its offset (T-895): one wording for both ends.
pub(super) use crate::keep_count::{dropped_line, reset_line};

/// Where the replay starts, and whether it is a reset: from `count`, the
/// client's offset, where the ring holds it; else from `base`, the offset
/// at the last detach; a reset where asked or where `count` cannot be
/// served.
pub(super) fn replay_from(ring: &Ring, base: u64, count: Option<u64>, reset: bool) -> (u64, bool) {
    let end = ring.end();
    let first = ring.start().unwrap_or(end);
    match (reset, count) {
        (true, _) => (first, true),
        (false, Some(count)) if count == end || (ring.start().is_some_and(|s| s <= count) && count <= end) => {
            (count, false)
        }
        (false, Some(_)) => (first, true),
        (false, None) => (base, false),
    }
}

/// The bytes of `ring` from the offset `from` on, and how many before them
/// are lost: a ring that dropped past `from` gives its bytes from its first
/// boundary instead (T-221), so that no part of a sequence shows as text.
pub(super) fn since(ring: &Ring, from: u64) -> (Vec<u8>, u64) {
    let end = ring.end();
    if from >= end {
        return (Vec::new(), 0);
    }
    match ring.start() {
        Some(start) if start <= from => {
            let kept = ring.kept();
            let skip = usize::try_from(from - start).unwrap_or(usize::MAX).min(kept.len());
            (kept[skip..].to_vec(), 0)
        }
        Some(start) => (ring.kept(), start - from),
        None => (Vec::new(), end - from),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// Each choice of replay or reset, one rule: a count that the ring
    /// holds replays from it; one past the output or before the ring, or a
    /// reset asked, gives the ring from its first boundary; no count starts
    /// at the detach.
    #[test]
    fn a_count_in_the_ring_replays_and_any_other_resets() {
        let mut ring = Ring::new(16);
        ring.push(b"0123456789abcdefghij", Instant::now());
        let (start, end) = (ring.start().expect("text is at a boundary"), ring.end());
        assert_eq!((start, end), (4, 20));
        let cases: &[(Option<u64>, bool, (u64, bool))] = &[
            (None, false, (12, false)),
            (Some(10), false, (10, false)),
            (Some(4), false, (4, false)),
            (Some(20), false, (20, false)),
            (Some(3), false, (4, true)),
            (Some(21), false, (4, true)),
            (Some(10), true, (4, true)),
            (None, true, (4, true)),
        ];
        for (count, reset, want) in cases {
            assert_eq!(replay_from(&ring, 12, *count, *reset), *want, "{count:?} {reset}");
        }
        assert_eq!(replay_from(&Ring::new(16), 0, Some(0), false), (0, false), "an empty ring");
    }
}
