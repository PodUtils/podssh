use std::sync::{Arc, Mutex};

use super::*;
use crate::accepted::{host_id, KeptFile};
use crate::escape::Command;
use crate::io::End;
use crate::keep_record::{self, Offsets, HEADER, MAX_AGE_MS, MOST};

const NOW: i64 = 1_790_000_000_000;

fn host(n: u8) -> String {
    host_id(&format!("user{n}"), b"host key")
}

/// Each line of serve's that tells of the offsets reads back to its number,
/// from the functions that serve writes it with; a reset's line with no
/// offset, a number that is not one, and any other line read as they
/// must: one rule for each line of stderr.
#[test]
fn serve_s_lines_read_back_to_their_offsets() {
    let unread = "podssh serve: a reset of the kept shell w: its last output follows, from a clean boundary\r\n";
    let other = "podssh serve: another client is attaching the shell w; try again\r\n";
    let unprefixed = reset_line("w", 5).replacen("podssh serve: ", "", 1);
    let cases: Vec<(String, Option<Said>)> = vec![
        (reset_line("work", 0), Some(Said::Reset(0))),
        (reset_line("a-b_9", 123_456_789), Some(Said::Reset(123_456_789))),
        (reset_line("w", u64::MAX), Some(Said::Reset(u64::MAX))),
        (dropped_line(1), Some(Said::Dropped(1))),
        (dropped_line(u64::MAX), Some(Said::Dropped(u64::MAX))),
        (unread.to_string(), Some(Said::Unread)),
        (reset_line("w", 5).replace(" 5\r\n", " +5\r\n"), Some(Said::Unread)),
        (dropped_line(7).replace("7 bytes", "-7 bytes"), Some(Said::Unread)),
        (dropped_line(7).replace("7 bytes", " bytes"), Some(Said::Unread)),
        (other.to_string(), None),
        (unprefixed, None),
        ("M=kept\r\n".to_string(), None),
    ];
    for (line, want) in cases {
        assert_eq!(said(&line), want, "{line:?}");
    }
}

enum Step {
    Out(usize),
    Err(Vec<u8>),
}

/// A case: its name, the count at the start, the steps, the count after.
type Case<'a> = (&'a str, Option<u64>, Vec<Step>, Option<u64>);

/// The count adds each byte of output, starts again at a reset's offset,
/// skips a dropped part's size, and is unknown after a line that does not
/// read or past the largest offset; a line cut in two pieces still reads,
/// and one longer than serve's is not read.
#[test]
fn the_count_follows_the_output_and_serve_s_lines() {
    use Step::{Err, Out};
    let reset = reset_line("work", 100).into_bytes();
    let (head, tail) = reset.split_at(20);
    let mut long = vec![b'x'; 600];
    long.extend_from_slice(&reset);
    let cases: Vec<Case> = vec![
        ("output", Some(10), vec![Out(5), Out(0), Out(2)], Some(17)),
        ("a reset", Some(10), vec![Out(3), Err(reset.clone()), Out(7)], Some(107)),
        ("a reset with no start", None, vec![Err(reset.clone()), Out(2)], Some(102)),
        ("a dropped part", Some(0), vec![Out(4), Err(dropped_line(100).into_bytes()), Out(1)], Some(105)),
        ("a line in two pieces", Some(1), vec![Err(head.to_vec()), Err(tail.to_vec()), Out(1)], Some(101)),
        ("a line longer than serve's", Some(1), vec![Err(long), Out(1)], Some(2)),
        ("another line", Some(1), vec![Err(b"podssh serve: no kept shell named w\r\n".to_vec()), Out(1)], Some(2)),
        ("an unread line", Some(1), vec![Err(dropped_line(3).replace('3', "x").into_bytes()), Out(1)], None),
        ("no start", None, vec![Out(5)], None),
        ("past the largest offset", Some(u64::MAX), vec![Out(1)], None),
    ];
    for (case, start, steps, want) in cases {
        let counter = Counter::starting(start);
        for step in steps {
            match step {
                Out(n) => counter.data(n),
                Err(bytes) => counter.stderr(&bytes),
            }
        }
        assert_eq!(counter.at(), want, "{case}");
    }
}

/// The list's line of a shell gives its offset; a line of another shell, a
/// lost shell, or a line with no offset (a far end that gives none) gives none.
#[test]
fn the_list_gives_a_shell_s_offset() {
    let text = "play detached 9\nwork attached 1234\nold lost\nbare detached\nodd detached x\n";
    let cases = [("work", Some(1234)), ("play", Some(9)), ("old", None), ("bare", None), ("odd", None), ("w", None)];
    for (name, want) in cases {
        assert_eq!(listed_offset(text, name), want, "{name}");
    }
    assert_eq!(listed_offset("", "work"), None);
}

/// The record's text reads back to the record; a text that does not read
/// is refused whole; an offset older than the longest lease is dropped; at
/// most [`MOST`] are kept, the oldest going first.
#[test]
fn the_record_reads_back_what_it_kept() {
    let mut record = Offsets::default();
    assert!(record.put(&host(1), "work", 42, NOW));
    assert!(record.put(&host(2), "work", 7, NOW - 5));
    assert!(!record.put("not-a-host", "work", 1, NOW), "an id that is none");
    assert!(!record.put(&host(1), "a b", 1, NOW), "a name that is none");
    let text = record.text();
    assert!(text.starts_with(&format!("{HEADER}\n")), "{text}");
    assert_eq!(Offsets::read(&text, NOW), Ok(record.clone()));
    assert_eq!(record.get(&host(1), "work"), Some(42));
    assert_eq!(record.get(&host(1), "play"), None);
    assert!(record.forget(&host(1), "work"));
    assert!(!record.forget(&host(1), "work"));

    let h = host(1);
    for bad in [
        String::new(),
        "podssh kept offsets 0\n".to_string(),
        format!("{HEADER}\n{h} work 1\n"),
        format!("{HEADER}\n{h} work x {NOW}\n"),
        format!("{HEADER}\n{h} work 1 x\n"),
        format!("{HEADER}\nabc work 1 {NOW}\n"),
        format!("{HEADER}\n{h} ../x 1 {NOW}\n"),
    ] {
        assert!(Offsets::read(&bad, NOW).is_err(), "{bad:?}");
    }
    let old = format!("{HEADER}\n{h} work 1 {}\n", NOW - MAX_AGE_MS);
    assert_eq!(Offsets::read(&old, NOW), Ok(Offsets::default()), "older than the longest lease");

    let mut full = Offsets::default();
    for n in 0..=MOST {
        assert!(full.put(&h, &format!("s{n}"), 1, NOW + n as i64));
    }
    assert_eq!(full.shells.len(), MOST);
    assert_eq!(full.get(&h, "s0"), None, "the oldest went");
    assert_eq!(full.get(&h, &format!("s{MOST}")), Some(1));
}

/// The record of this test process, in memory.
struct Memory(Arc<Mutex<Option<String>>>);

impl KeptFile for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

/// At a session's end, the offset is kept where the shell may still be
/// kept (a lost link, `~.`, a signal, `~d` under the far end's name), and
/// forgotten where the shell ended, where another client took it, and
/// where the offset is not known; a session that got nothing of the shell
/// (a refused join) leaves what was kept: one rule for each end.
#[test]
fn a_session_s_end_keeps_or_forgets_the_offset() {
    let file = Arc::new(Mutex::new(None));
    assert!(keep_record::keep_in(Box::new(Memory(file.clone()))), "the only test that keeps a record");
    let h = host(3);
    // Each end, the start, the output after it, and what is kept then.
    let cases: Vec<(End, Option<u64>, usize, Option<u64>)> = vec![
        (End::Lost, Some(5), 1, Some(6)),
        (End::Lost, Some(5), 0, Some(5)),
        (End::Escaped(Command::Disconnect), Some(6), 1, Some(7)),
        (End::Terminated, Some(7), 1, Some(8)),
        (End::Interrupted, Some(8), 1, Some(9)),
        (End::Detached("work".into()), Some(9), 1, Some(10)),
        (End::Status(0), Some(10), 1, None),
        (End::Cut(0), Some(11), 1, None),
        (End::NoStatus, Some(12), 1, None),
        (End::Status(1), Some(13), 0, Some(1)),
        (End::Lost, None, 1, None),
        (End::Status(1), None, 0, Some(1)),
    ];
    for (end, at, output, want) in cases {
        keep_record::save(&h, "work", 1);
        let counting = Counting { host: h.clone(), name: Some("work".into()), counter: Counter::starting(at) };
        counting.counter.data(output);
        counting.ended(&end);
        assert_eq!(keep_record::saved(&h, "work"), Ok(want), "{end:?} at {at:?} and {output} more");
    }
    // A count that the far end refused is unknown, and moved: forgotten.
    let refused = Counting { host: h.clone(), name: Some("work".into()), counter: Counter::starting(Some(4)) };
    refused.counter.unknown();
    refused.ended(&End::Status(0));
    assert_eq!(keep_record::saved(&h, "work"), Ok(None));
    // `~d` keeps the shell under a name of its own: the offset goes there.
    keep_record::save(&h, "work", 1);
    let counting = Counting { host: h.clone(), name: Some("work".into()), counter: Counter::starting(Some(20)) };
    counting.ended(&End::Detached("1a2b3c4d".into()));
    assert_eq!(keep_record::saved(&h, "work"), Ok(None));
    assert_eq!(keep_record::saved(&h, "1a2b3c4d"), Ok(Some(20)));
    // A new shell with no name is kept only by `~d`.
    let unnamed = Counting { host: h.clone(), name: None, counter: Counter::starting(Some(30)) };
    unnamed.ended(&End::Lost);
    unnamed.ended(&End::Detached("5e6f7a8b".into()));
    assert_eq!(keep_record::saved(&h, "5e6f7a8b"), Ok(Some(30)));
    assert!(file.lock().unwrap().as_deref().is_some_and(|text| !text.contains("work")), "the record holds no work");
}
