//! The records of the frames (T-303): each version reads back across any
//! cut, and each header or line section that is no frame is refused, on
//! one table each.

use super::*;

fn head(number: u64, base: u64) -> Head {
    Head { full: base == 0, bell: false, last: false, number, base, rows: 24, cols: 80, total: 0 }
}

fn lines(texts: &[&str]) -> Vec<Vec<u8>> {
    texts.iter().map(|text| text.as_bytes().to_vec()).collect()
}

/// Each frame of each version reads back the same, however SSH cuts the
/// stream; version 1 says no count of lines and carries none.
#[test]
fn a_frame_reads_back_across_any_cut() {
    let sent = [
        (Version::Two, Frame { head: head(1, 0), lines: Vec::new(), body: b"\x1b[H\x1b[Jone".to_vec() }),
        (Version::One, Frame { head: Head { bell: true, ..head(2, 1) }, lines: Vec::new(), body: Vec::new() }),
        (
            Version::Two,
            Frame {
                head: Head { rows: 60, cols: 200, total: 9, ..head(u64::MAX, 7) },
                lines: lines(&["line 8", "", "\x1b[31mline 9\x1b[m"]),
                body: vec![b'x'; 3000],
            },
        ),
        (
            Version::Two,
            Frame {
                head: Head { last: true, total: 1, ..head(9, 0) },
                lines: lines(&["caf\u{e9}"]),
                body: "caf\u{e9} \u{4e16}".as_bytes().to_vec(),
            },
        ),
        (Version::Two, Frame { head: Head { total: u64::MAX, ..head(10, 9) }, lines: Vec::new(), body: Vec::new() }),
    ];
    let stream: Vec<u8> = sent.iter().flat_map(|(v, f)| encode(*v, f.head, &f.lines, &f.body)).collect();
    for cut in [1, 2, 7, HEADER_V1 - 1, HEADER_V1, HEADER - 1, HEADER, HEADER + 1, 1000, stream.len()] {
        let mut decoder = Decoder::default();
        let got: Vec<Frame> = stream.chunks(cut).flat_map(|c| decoder.feed(c).unwrap()).collect();
        let want: Vec<Frame> = sent.iter().map(|(_, f)| f.clone()).collect();
        assert_eq!(got, want, "cut every {cut} bytes");
        assert!(decoder.part.is_empty(), "nothing is left after the last frame (cut {cut})");
    }
}

/// Version 1 carries no line and no count: a sender of version 1 drops
/// them, so an older client reads each frame.
#[test]
fn version_1_carries_no_line_and_no_count() {
    let bytes = encode(Version::One, Head { total: 5, ..head(3, 2) }, &lines(&["a", "b"]), b"body");
    assert_eq!((bytes[0], bytes.len()), (1, HEADER_V1 + 4));
    let frame = &Decoder::default().feed(&bytes).unwrap()[0];
    assert_eq!((frame.head.total, frame.lines.len(), &frame.body[..]), (0, 0, &b"body"[..]));
}

/// The sender keeps only the lines that the count names: never more lines
/// than left the screen.
#[test]
fn a_frame_carries_no_more_lines_than_left_the_screen() {
    let bytes = encode(Version::Two, Head { total: 2, ..head(1, 0) }, &lines(&["a", "b", "c"]), b"");
    let frame = &Decoder::default().feed(&bytes).unwrap()[0];
    assert_eq!(frame.lines, lines(&["b", "c"]));
    let bytes = encode(Version::Two, head(1, 0), &lines(&["a"]), b"");
    assert!(Decoder::default().feed(&bytes).unwrap()[0].lines.is_empty(), "none left: none goes");
}

/// A header that is no frame of its version is refused, each field by one
/// rule: the place of the byte, its value, and the word of the refusal.
#[test]
fn a_header_of_another_version_or_with_no_state_is_refused() {
    for version in [Version::One, Version::Two] {
        let good = encode(version, head(5, 4), &[], b"body");
        assert_eq!(Decoder::default().feed(&good).unwrap().len(), 1);
        let mut cases: Vec<(&str, usize, u8, &str)> = vec![
            ("another version", 0, 3, "cannot read"),
            ("no version", 0, 0, "cannot read"),
            ("a flag that no version has", 1, 16, "cannot read"),
            ("the number 0", 9, 0, "no state"),
            ("a base that is not before the number", 17, 5, "no state"),
            ("a whole screen with a base", 1, FULL, "no state"),
            ("no rows", 19, 0, "no state"),
            ("no columns", 21, 0, "no state"),
            ("a body above the most", 22, 0xff, "above the most"),
        ];
        if version == Version::One {
            cases.push(("the flag of the lines, which version 1 does not have", 1, LINES, "cannot read"));
        }
        for (what, at, value, word) in cases {
            let mut bad = good.clone();
            bad[at] = value;
            let refused = Decoder::default().feed(&bad).expect_err(what);
            assert!(refused.contains(word), "{version:?}, {what}: {refused}");
        }
    }
}

/// The lines of a frame of version 2 that are no lines are refused: one
/// table of the bytes after the header, with the count that left the
/// screen and the word of the refusal.
#[test]
fn lines_that_overrun_the_body_or_the_count_are_refused() {
    let cases: &[(&str, &[u8], u64, &str)] = &[
        ("no count", b"\x00", 5, "overrun"),
        ("a count of 0", b"\x00\x00", 5, "0 lines"),
        ("more lines than left the screen", b"\x00\x02\x00\x01a\x00\x01b", 1, "2 lines, where 1"),
        ("a line longer than the body", b"\x00\x01\x00\x09abc", 5, "overrun"),
        ("fewer lines than the count", b"\x00\x02\x00\x01a", 5, "overrun"),
        ("a length cut in two", b"\x00\x02\x00\x01a\x00", 5, "overrun"),
    ];
    for (what, rest, total, word) in cases {
        let mut bytes = encode(Version::Two, Head { total: *total, ..head(1, 0) }, &[], b"");
        bytes[1] |= LINES;
        bytes[22..26].copy_from_slice(&(rest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(rest);
        let refused = Decoder::default().feed(&bytes).expect_err(what);
        assert!(refused.contains(word), "{what}: {refused}");
    }
}

/// A body above the most is cut by the sender, so its frame still reads.
#[test]
fn a_body_above_the_most_is_cut_at_the_most() {
    let bytes = encode(Version::Two, head(1, 0), &[], &vec![b'a'; MAX_BODY + 9]);
    assert_eq!(bytes.len(), HEADER + MAX_BODY);
    let frames = Decoder::default().feed(&bytes).unwrap();
    assert_eq!(frames[0].body.len(), MAX_BODY);
}

/// Each version's word reads back; another word is no version.
#[test]
fn a_version_is_asked_by_its_word() {
    assert_eq!(Version::ASKED.map(Version::word), ["v2", "v1"], "the newest first");
    assert_eq!(VERSION, Version::Two.word());
    for version in Version::ASKED {
        assert_eq!(Version::of(version.word()), Some(version));
    }
    for bad in ["", "v0", "v3", "V2", "v2 ", "2"] {
        assert_eq!(Version::of(bad), None, "{bad:?}");
    }
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
