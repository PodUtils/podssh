//! What ends a transfer whatever the far end does (T-859), each way, while a
//! write of the session's bytes still waits for the server: Ctrl-C, five CAN
//! typed (in two reads), the write's limit of 40 s, and the local terminal's
//! end. Each says one line, sends the cancel sequence, drops the write that
//! waits, and keeps no file that did not end; four CAN end nothing.

use std::io::Cursor;
use std::time::{Duration, Instant};

use podssh_ssh::zmodem::receive::{Receiver, FLAGS};
use podssh_ssh::zmodem::send::Sender;
use podssh_ssh::zmodem::wire;
use podssh_ssh::zmodem::{Act, Zmodem, CANCEL, TRIES, WAIT};

use super::super::{outgoing, read_header, split};
use super::scratch;

/// How a transfer is ended.
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
                let limit = WAIT * TRIES;
                assert!(z.deadline().is_some_and(|due| due <= now + limit), "the write's limit bounds each wait");
                z.tick(now + limit);
                "the server took nothing that podssh sent for 40 s"
            }
            How::Hangup => {
                z.hangup(now);
                "the local terminal went"
            }
        }
    }
}

/// A download into `dir` halfway through its first subpacket, with the
/// session's answer (ZRPOS) not yet written.
fn receiving(dir: &std::path::Path, now: Instant) -> Zmodem {
    let mut z = Zmodem::new();
    z.output(&wire::hex_header(wire::ZRQINIT, [0; 4]), now);
    z.keys(format!("{}\r", dir.display()).into_bytes(), now);
    let header = read_header(&z.take(now).server);
    z.written();
    let data = vec![7u8; 10_000];
    let (mut sender, first) = Sender::new(Cursor::new(data.clone()), outgoing("big.bin", data.len()), &header, now);
    z.output(&split(first).0, now);
    let zrpos = z.take(now).server;
    assert!(split(sender.feed(&zrpos, now)).1.is_empty());
    let part = split(sender.pull(now)).0;
    z.output(&part[..part.len() / 2], now);
    assert_eq!(std::fs::read_dir(dir).expect("the directory").count(), 1, "the temporary file");
    z
}

/// An upload of a file of `dir` to `rz`, streaming, its last bytes not yet
/// written.
fn sending(dir: &std::path::Path, now: Instant) -> Zmodem {
    let path = dir.join("up.bin");
    std::fs::write(&path, vec![9u8; 200_000]).expect("a file");
    let mut z = Zmodem::new();
    z.output(&wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS]), now);
    z.keys(format!("{}\r", path.display()).into_bytes(), now);
    let zfile = z.take(now).server;
    z.written();
    let (mut receiver, _) = Receiver::new(now);
    let (_, acts) = split(receiver.feed(&zfile, now));
    let offer = acts.iter().any(|a| matches!(a, Act::Offer(_)));
    assert!(offer, "rz is offered the file");
    z.output(&split(receiver.decide(true, now)).0, now);
    assert!(z.more(), "the file streams");
    assert!(!z.take(now).server.is_empty(), "a write of the file waits");
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
            let taken = z.take(now);
            assert_eq!(taken.server, CANCEL, "{case}: the cancel sequence goes");
            let screen = String::from_utf8_lossy(&taken.screen).into_owned();
            assert_eq!(screen.matches("ZMODEM:").count(), 1, "{case}: one line: {screen:?}");
            assert!(screen.contains(&format!("podssh: ZMODEM: {why}\r\n")), "{case}: {screen:?}");
            let left: Vec<_> =
                std::fs::read_dir(&dir).expect("the directory").map(|e| e.expect("an entry").file_name()).collect();
            let want = if way == "send" { vec![std::ffi::OsString::from("up.bin")] } else { Vec::new() };
            assert_eq!(left, want, "{case}: no file that did not end is kept");
        }
    }
}

/// Four CAN, or five that a key cuts, end nothing: CAN is a byte of the
/// keys too, and only five in a row are the spec's abort (7.2). A stream
/// that the server takes has no wait of the protocol; the write's limit is
/// its only time, and it does not end it before 40 s.
#[test]
fn four_can_or_five_cut_by_a_key_or_39_s_end_nothing() {
    let now = Instant::now();
    let dir = scratch("end-four-can");
    let mut z = sending(&dir, now);
    z.keys(b"\x18\x18\x18\x18".to_vec(), now);
    z.keys(b"a\x18".to_vec(), now);
    let limit = WAIT * TRIES;
    assert_eq!(z.deadline(), Some(now + limit), "the write's limit is the stream's wait");
    z.tick(now + limit - Duration::from_millis(1));
    assert!(z.transferring(), "the transfer goes on");
    assert!(!z.abandoned());
    // The write went: the next has a limit of its own.
    z.written();
    assert_eq!(z.deadline(), None);
}
