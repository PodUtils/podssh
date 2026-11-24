//! The keys of one read of the terminal, as local echo guesses them (T-160):
//! the few whose effect on the cursor's row is plain, and each other key as
//! one that no guess follows.

/// One key, as local echo reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Key {
    /// A printable ASCII character: it shows at the cursor, which moves on.
    Text(char),
    /// DEL or BS: the character before the cursor goes.
    Erase,
    /// The left arrow, in either cursor mode (`ESC [ D`, `ESC O D`).
    Left,
    /// The right arrow (`ESC [ C`, `ESC O C`).
    Right,
    /// Anything else: Enter, Tab, a control key, another sequence, a
    /// character that is not ASCII. What it does is the far end's to say,
    /// so no guess follows it until the far end has read it.
    Other,
}

/// The keys of `data`, each with its length in bytes. A sequence that the
/// read cuts, or that is not an arrow, is [`Key::Other`] with each byte
/// after it: nothing after it is guessed anyway.
pub(super) fn keys(data: &[u8]) -> Vec<(Key, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let (key, len) = match data[i] {
            b @ 0x20..=0x7e => (Key::Text(char::from(b)), 1),
            0x7f | 0x08 => (Key::Erase, 1),
            0x1b => match data.get(i + 1..i + 3) {
                Some(b"[C" | b"OC") => (Key::Right, 3),
                Some(b"[D" | b"OD") => (Key::Left, 3),
                _ => (Key::Other, data.len() - i),
            },
            _ => (Key::Other, 1),
        };
        out.push((key, len));
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each key of a table reads as its row says, and the lengths add up to
    /// the read.
    #[test]
    fn each_key_reads_as_the_table_says() {
        let rows: &[(&[u8], &[Key])] = &[
            (b"ls", &[Key::Text('l'), Key::Text('s')]),
            (b" ~", &[Key::Text(' '), Key::Text('~')]),
            (b"\x7f\x08", &[Key::Erase, Key::Erase]),
            (b"\x1b[D\x1bOC", &[Key::Left, Key::Right]),
            (b"a\r", &[Key::Text('a'), Key::Other]),
            (b"\t\x03\x15", &[Key::Other, Key::Other, Key::Other]),
            (b"\x1b[A", &[Key::Other]),
            (b"\x1b[", &[Key::Other]),
            (b"\x1b", &[Key::Other]),
            ("é".as_bytes(), &[Key::Other, Key::Other]),
            (b"\x1b[200~x", &[Key::Other]),
        ];
        for (data, want) in rows {
            let got = keys(data);
            let kinds: Vec<Key> = got.iter().map(|(k, _)| *k).collect();
            assert_eq!(&kinds, want, "{data:?}");
            assert_eq!(got.iter().map(|(_, n)| n).sum::<usize>(), data.len(), "{data:?}");
        }
    }
}
