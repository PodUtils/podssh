//! What ends a transfer of the 7-bit envelope whatever the far end does
//! (T-859's paths, T-831), each way, while a write of the session's bytes
//! still waits for the server: Ctrl-C, five CAN typed in two reads, the
//! write's limit, and the local terminal's end. Each says one line, drops
//! the write that waits, sends `STOP` with code 1 next, and keeps no file
//! that did not end; four CAN end nothing.

use std::time::{Duration, Instant};

use podssh_ssh::zmodem::Zmodem;

use super::{far, names, near, output, scratch, step, ACKN, DATA, HELO, OFFR, TAKE, TRIGGER_R, TRIGGER_S};

/// The write limit of these tests, in place of 40 s: under the codec's
/// 20 s wait, so that the limit is what ends.
const LIMIT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
enum How {
    CtrlC,
    Can,
    Limit,
    Hangup,
}

impl How {
    /// End the transfer of `z` at `now`; the words of its line.
    fn end(self, z: &mut Zmodem, now: Instant) -> &'static str {
        match self {
            How::CtrlC => {
                assert!(z.keys(b"x\x03".to_vec(), now).is_empty());
                "cancelled here (Ctrl-C)"
            }
            How::Can => {
                assert!(z.keys(b"\x18\x18".to_vec(), now).is_empty());
                assert!(z.transferring(), "two CAN end nothing");
                assert!(z.keys(b"\x18\x18\x18".to_vec(), now).is_empty());
                "cancelled here (CAN)"
            }
            How::Limit => {
                assert!(z.deadline().is_some_and(|due| due <= now + LIMIT), "the write's limit bounds each wait");
                z.tick(now + LIMIT);
                "the server took nothing that podssh sent for 1 s"
            }
            How::Hangup => {
                z.hangup(now);
                "the local terminal went"
            }
        }
    }
}

/// A download into `dir` after its first `DATA`, the answer (`ACKN`) taken
/// and its write not ended.
fn receiving(dir: &std::path::Path, now: Instant) -> Zmodem {
    let mut z = Zmodem::new().with_limit(LIMIT);
    output(&mut z, TRIGGER_S, now);
    z.keys(format!("{}\r", dir.display()).into_bytes(), now);
    step(&mut z, Vec::new(), now);
    output(&mut z, &far(HELO), now);
    output(&mut z, &far(OFFR), now);
    let shown = z.output(&far(DATA), now);
    assert!(!shown.is_empty(), "the progress shows");
    assert_eq!(z.take(now).server, near(ACKN), "a write of the answer waits");
    assert_eq!(names(dir).len(), 1, "the temporary file");
    z
}

/// An upload of a file of `dir`, its first `DATA` taken and its write not
/// ended.
fn sending(dir: &std::path::Path, now: Instant) -> Zmodem {
    let path = dir.join("a.txt");
    std::fs::write(&path, b"hello\n").expect("a file");
    let mut z = Zmodem::new().with_limit(LIMIT);
    output(&mut z, TRIGGER_R, now);
    z.keys(format!("{}\r", path.display()).into_bytes(), now);
    step(&mut z, Vec::new(), now);
    output(&mut z, &far(HELO), now);
    z.output(&far(TAKE), now);
    assert_eq!(z.take(now).server, near(DATA), "a write of the file waits");
    z
}

#[test]
fn each_end_of_a_transfer_says_one_line_and_keeps_no_file() {
    let now = Instant::now();
    for how in [How::CtrlC, How::Can, How::Limit, How::Hangup] {
        for way in ["receive", "send"] {
            let dir = scratch(&format!("end-{how:?}-{way}"));
            let mut z = if way == "receive" { receiving(&dir, now) } else { sending(&dir, now) };
            let why = how.end(&mut z, now);
            let case = format!("{how:?} {way}");
            assert!(!z.busy() && !z.transferring(), "{case}: the transfer ended");
            assert!(z.abandoned(), "{case}: the write that waits is dropped");
            z.written();
            let taken = z.take(now + LIMIT);
            // The frame in flight may go once more before it: `STOP` ends the bytes.
            let server = String::from_utf8_lossy(&taken.server).into_owned();
            assert!(server.starts_with("#") && server.contains("#STOP:AQ"), "{case}: STOP 1 goes: {server:?}");
            assert!(server.ends_with('\r'), "{case}: {server:?}");
            let screen = String::from_utf8_lossy(&taken.screen).into_owned();
            assert_eq!(screen.matches("podssh: tx: ").count(), 1, "{case}: one line: {screen:?}");
            assert!(screen.contains(&format!("podssh: tx: {why}\r\n")), "{case}: {screen:?}");
            let want = if way == "send" { vec!["a.txt".to_string()] } else { Vec::new() };
            assert_eq!(names(&dir), want, "{case}: no file that did not end is kept");
        }
    }
}

/// Four CAN, or five that a key cuts, end nothing: only five in a row do.
#[test]
fn four_can_or_five_cut_by_a_key_end_nothing() {
    let now = Instant::now();
    let dir = scratch("end-four-can");
    let mut z = receiving(&dir, now);
    z.written();
    assert!(z.keys(b"\x18\x18\x18\x18".to_vec(), now).is_empty());
    assert!(z.keys(b"a\x18".to_vec(), now).is_empty());
    assert!(z.transferring(), "the transfer goes on");
    assert!(z.take(now).server.is_empty(), "no STOP");
}
