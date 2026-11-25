//! The 7-bit envelope in a session (T-831): `pod_term::transfer` as podssh
//! wires it into the session's watch of the output, beside ZMODEM. The
//! vectors are those of `docs/terminal.md` ("The 7-bit envelope (T-831,
//! step 2)"), each frame computed with Python's `base64` and `zlib.crc32`,
//! not by this crate or the codec: the near end's scan for the trigger, a
//! file each way frame by frame, and the faults that end a transfer with
//! `STOP`. Then each end of a transfer whatever the far end does
//! (`tests/envelope_ends/mod.rs`, T-859's paths), and a file each way
//! through a terminal between the far end and the pty that draws its own
//! screen, as tmux does (`tests/envelope_damage/mod.rs`).

mod cleanup;
mod envelope_damage;
mod envelope_ends;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use podssh_ssh::zmodem::Zmodem;

/// The trigger of a download and of an upload, as the far end paints them.
const TRIGGER_S: &[u8] = b"\r\x1b[K#PODSSH-TX2:S:0123456789abcdef:f9541cc2\r\n";
const TRIGGER_R: &[u8] = b"\r\x1b[K#PODSSH-TX2:R:0123456789abcdef:1606aa23\r\n";

/// The frames of the exchanges, without their line end: `a.txt`, the 6
/// bytes `hello\n`, mode 0644, mtime 0; the codec's version 2.
const HELO: &str = "#HELO:AgEjRWeJq83vAACAAA!9c5e7795";
const OFFR: &str = "#OFFR:AAAAAAAAAAYAAAGkAAAAAAAAAAAABWEudHh0!51054221";
const TAKE: &str = "#TAKE:AAAAAAAAAAA!5b64f8f9";
const DATA: &str = "#DATA:AAAAAAAAAABoZWxsbwo!beee1f4d";
const ACKN: &str = "#ACKN:AAAAAAAAAAAAAAAAAAAABg!168c223e";
const DONE: &str = "#DONE:AAAAAAAAAAZYkbW1ItXfCG0P8LEQ+9nSG7T8cWOvNNCChqLoRva+Aw!6ff6dfbc";
const KEPT: &str = "#KEPT:AAAAAAAAAAY!67cdbc05";
const HOLD: &str = "#HOLD:!464f8be9";

/// A frame from the far end: CRLF, as its raw tty has it.
fn far(frame: &str) -> Vec<u8> {
    format!("{frame}\r\n").into_bytes()
}

/// A frame from the near end: CR, the Enter key.
fn near(frame: &str) -> Vec<u8> {
    format!("{frame}\r").into_bytes()
}

/// A directory of its own for a test, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-envelope-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the directory")
        .map(|e| e.expect("an entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// One step of the session's pump: what the terminal shows and what goes
/// to the server, the write ended at once.
#[derive(Debug, Default)]
struct Step {
    screen: String,
    server: Vec<u8>,
}

fn step(z: &mut Zmodem, shown: Vec<u8>, now: Instant) -> Step {
    let taken = z.take(now);
    z.written();
    let screen = [shown, taken.screen].concat();
    Step { screen: String::from_utf8_lossy(&screen).into_owned(), server: taken.server }
}

fn output(z: &mut Zmodem, bytes: &[u8], now: Instant) -> Step {
    let shown = z.output(bytes, now);
    step(z, shown, now)
}

fn keys(z: &mut Zmodem, bytes: &[u8], now: Instant) -> Step {
    let passed = z.keys(bytes.to_vec(), now);
    assert!(passed.is_empty(), "a question or a transfer takes each key: {passed:?}");
    step(z, Vec::new(), now)
}

/// The rows T: the near end's scan of the output. A trigger whose CRC
/// holds, of version 2 and with a new id, starts a question and never
/// shows; each other line shows unchanged, and nothing goes to the server.
#[test]
fn the_scan_starts_a_question_only_for_a_whole_new_trigger() {
    let now = Instant::now();
    let rows: &[(&str, &[u8], Option<&str>, &str)] = &[
        ("T1", b"ls\r\n#PODSSH-TX2:S:0123456789abcdef:f9541cc2\r\n", Some("Receive into"), "ls\r\n"),
        ("T2", b"#PODSSH-TX2:R:0123456789abcdef:1606aa23\r\n", Some("Send which file?"), ""),
        ("T5", b"#PODSSH-TX2:S:0123456789abcdef:f9541cc3\r\n", None, "#PODSSH-TX2:S:0123456789abcdef:f9541cc3\r\n"),
        ("T6", b"#PODSSH-TX1:S:0123456789abcdef:56fd5108\r\n", None, "#PODSSH-TX1:S:0123456789abcdef:56fd5108"),
        ("T6", b"#PODSSH-TX3:S:0123456789abcdef:9c332784\r\n", None, "#PODSSH-TX3:S:0123456789abcdef:9c332784"),
        ("T9", b"#PODSSH-TX2:S:0123\x1b[K456789abcdef:f9541cc2\r\n", None, "#PODSSH-TX2:S:0123\x1b[K456789abcdef"),
    ];
    for (row, input, question, shown) in rows {
        let mut z = Zmodem::new();
        let s = output(&mut z, input, now);
        assert!(s.screen.starts_with(shown), "{row}: {:?}", s.screen);
        assert!(s.server.is_empty(), "{row}: nothing goes before an answer");
        match question {
            Some(q) => {
                assert!(s.screen.contains(q) && z.busy(), "{row}: {:?}", s.screen);
                assert!(!s.screen.contains("#PODSSH-TX"), "{row}: the trigger shows: {:?}", s.screen);
            }
            None => assert!(!z.busy(), "{row}: a line that is no trigger starts nothing"),
        }
    }
    // T6, X20: a version that this podssh does not speak is said, once.
    let s = output(&mut Zmodem::new(), b"#PODSSH-TX1:S:0123456789abcdef:56fd5108\r\n", now);
    assert_eq!(s.screen.matches("speaks version 1").count(), 1, "{:?}", s.screen);
}

/// T3, T4: a trigger cut by a read waits for its rest 100 ms, then shows.
#[test]
fn a_trigger_cut_by_a_read_waits_100_ms() {
    let now = Instant::now();
    let mut z = Zmodem::new();
    assert_eq!(output(&mut z, b"#PODSSH-TX2:S:0123", now).screen, "");
    let s = output(&mut z, b"456789abcdef:f9541cc2\r\n", now);
    assert!(s.screen.contains("Receive into"), "T3: {:?}", s.screen);
    let mut z = Zmodem::new();
    assert_eq!(output(&mut z, b"#PODSSH-TX2:S:0123", now).screen, "");
    assert_eq!(z.deadline(), Some(now + Duration::from_millis(100)));
    z.tick(now + Duration::from_millis(100));
    assert_eq!(step(&mut z, Vec::new(), now).screen, "#PODSSH-TX2:S:0123", "T4");
}

/// T7, T8: a trigger seen before (tmux paints its screen again) starts
/// nothing once its session ended; a new id starts one.
#[test]
fn a_trigger_seen_before_shows_and_a_new_id_starts() {
    let now = Instant::now();
    let mut z = Zmodem::new();
    output(&mut z, TRIGGER_S, now);
    let s = keys(&mut z, b"\x03", now);
    assert_eq!(s.server, near("#STOP:BgAMcmVmdXNlZCBoZXJl!cffba5b2"), "X7: refused here");
    assert!(!z.busy());
    let again = output(&mut z, &TRIGGER_S[4..], now);
    assert!(again.screen.contains("#PODSSH-TX2:S:0123456789abcdef:f9541cc2") && !z.busy(), "T7");
    let s = output(&mut z, b"#PODSSH-TX2:S:fedcba9876543210:756e6da1\r\n", now);
    assert!(s.screen.contains("Receive into") && z.busy(), "T8: {:?}", s.screen);
}

/// The download of the vectors: each frame that podssh sends is the
/// vector's, byte for byte; the file comes under a temporary name, and the
/// rename after `DONE`'s SHA-256 gives it its name and its mode.
#[test]
fn a_download_sends_the_frames_of_the_vectors_and_keeps_the_file() {
    let now = Instant::now();
    let dir = scratch("download");
    let mut z = Zmodem::new();
    let s = output(&mut z, TRIGGER_S, now);
    assert!(s.screen.contains("podssh tx send") && s.server.is_empty(), "{:?}", s.screen);
    let steps: &[(Vec<u8>, Vec<u8>)] = &[
        (Vec::new(), near(HELO)),
        (far(HELO), Vec::new()),
        (far(OFFR), near(TAKE)),
        (far(DATA), near(ACKN)),
        (far(DONE), near(KEPT)),
    ];
    let mut screen = keys_then(&mut z, &dir, &steps[0].1, now);
    for (input, want) in &steps[1..] {
        let s = output(&mut z, input, now);
        assert_eq!(String::from_utf8_lossy(&s.server), String::from_utf8_lossy(want), "after {input:?}");
        screen.push_str(&s.screen);
    }
    assert!(!z.busy(), "the session ended");
    assert_eq!(std::fs::read(dir.join("a.txt")).expect("the file"), b"hello\n");
    assert_eq!(names(&dir), ["a.txt"], "no temporary file is left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("a.txt")).expect("its mode").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
    assert!(screen.contains("received ") && screen.contains("(6 bytes, SHA-256 checked)"), "{screen:?}");
    // The shell's prompt after the end shows again.
    assert_eq!(output(&mut z, b"$ ", now).screen, "$ ");
}

/// The answer to the question of a download: the directory, then Enter.
fn keys_then(z: &mut Zmodem, dir: &Path, want: &[u8], now: Instant) -> String {
    let s = keys(z, format!("{}\r", dir.display()).as_bytes(), now);
    assert_eq!(String::from_utf8_lossy(&s.server), String::from_utf8_lossy(want));
    s.screen
}

/// The upload of the vectors: podssh's `OFFR`, `DATA` and `DONE` are the
/// vector's (the mode and the time of the file as the vector has them).
#[test]
fn an_upload_sends_the_frames_of_the_vectors() {
    let now = Instant::now();
    let dir = scratch("upload");
    let path = dir.join("a.txt");
    std::fs::write(&path, b"hello\n").expect("a file");
    let file = std::fs::File::options().write(true).open(&path).expect("the file");
    file.set_modified(std::time::UNIX_EPOCH).expect("its time");
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("its mode");
    }
    let mut z = Zmodem::new();
    let s = output(&mut z, TRIGGER_R, now);
    assert!(s.screen.contains("Send which file?"), "{:?}", s.screen);
    assert_eq!(keys(&mut z, format!("{}\r", path.display()).as_bytes(), now).server, near(HELO));
    let offr = output(&mut z, &far(HELO), now).server;
    // Windows keeps no mode: its OFFR says 0 there, and differs from the vector.
    if cfg!(unix) {
        assert_eq!(String::from_utf8_lossy(&offr), String::from_utf8_lossy(&near(OFFR)));
    }
    assert_eq!(output(&mut z, &far(TAKE), now).server, near(DATA), "the chunk is 1 KiB: the whole file");
    assert_eq!(output(&mut z, &far(ACKN), now).server, near(DONE));
    let end = output(&mut z, &far(KEPT), now);
    assert!(end.server.is_empty() && !z.busy());
    assert!(end.screen.contains("sent a.txt (6 bytes, SHA-256 checked by the server)"), "{:?}", end.screen);
}

/// The faults of a download that end it from here: each sends its `STOP`
/// (the vector's bytes), says one line, and keeps no file.
#[test]
fn each_fault_of_a_download_sends_its_stop_and_keeps_nothing() {
    let now = Instant::now();
    #[derive(Debug, Clone)]
    enum Act {
        Out(Vec<u8>),
        Keys(&'static [u8]),
        After(Duration),
    }
    let through_data = || vec![Act::Out(far(HELO)), Act::Out(far(OFFR)), Act::Out(far(DATA))];
    let rows: Vec<(&str, Vec<Act>, &str, &str)> = vec![
        (
            "X4 a SHA-256 that differs",
            [
                through_data(),
                vec![Act::Out(far("#DONE:AAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!b65d2465"))],
            ]
            .concat(),
            "#STOP:AwAhU0hBLTI1NiBkaWZmZXJzOyBub3RoaW5nIHdhcyBrZXB0!59691c9e",
            "tx: SHA-256 differs; nothing was kept",
        ),
        (
            "X5 Ctrl-C",
            [through_data(), vec![Act::Keys(b"\x03")]].concat(),
            "#STOP:AQAXY2FuY2VsbGVkIGhlcmUgKEN0cmwtQyk!7306070e",
            "tx: cancelled here (Ctrl-C)",
        ),
        (
            "X6 five CAN in two reads",
            [through_data(), vec![Act::Keys(b"\x18\x18"), Act::Keys(b"\x18\x18\x18")]].concat(),
            "#STOP:AQAUY2FuY2VsbGVkIGhlcmUgKENBTik!f4d1116f",
            "tx: cancelled here (CAN)",
        ),
        (
            "X10 a name that names no file",
            vec![Act::Out(far(HELO)), Act::Out(far("#OFFR:AAAAAAAAAAYAAAGkAAAAAAAAAAAAAi4u!4533a1d9"))],
            "#STOP:BgAbdGhlIG5hbWUgbmFtZXMgbm8gZmlsZSBoZXJl!077e5dcc",
            "tx: the name names no file here",
        ),
        (
            "X11 silence",
            vec![Act::Out(far(HELO)), Act::Out(far(OFFR)), Act::After(Duration::from_secs(20))],
            "#STOP:AgAfbm8gYW5zd2VyIGZyb20gdGhlIHBlZXIgaW4gdGltZQ!d67b841b",
            "tx: no answer from the peer in time",
        ),
    ];
    for (name, acts, stop, line) in rows {
        let dir = scratch(&format!("fault-{}", &name[..3].trim()));
        let mut z = Zmodem::new();
        output(&mut z, TRIGGER_S, now);
        keys(&mut z, format!("{}\r", dir.display()).as_bytes(), now);
        let (mut screen, mut last) = (String::new(), Vec::new());
        for act in acts {
            let s = match act {
                Act::Out(bytes) => output(&mut z, &bytes, now),
                Act::Keys(bytes) => keys(&mut z, bytes, now),
                Act::After(wait) => {
                    z.tick(now + wait);
                    step(&mut z, Vec::new(), now + wait)
                }
            };
            screen.push_str(&s.screen);
            last = s.server;
        }
        assert_eq!(String::from_utf8_lossy(&last), String::from_utf8_lossy(&near(stop)), "{name}");
        assert!(!z.busy(), "{name}: the session ended");
        assert_eq!(screen.matches("podssh: tx: ").count(), 1, "{name}: one line: {screen:?}");
        assert!(screen.contains(line), "{name}: {screen:?}");
        assert_eq!(names(&dir), Vec::<String>::new(), "{name}: no file is kept");
    }
}

/// The faults of an upload, where podssh sends: a lost ack sends the same
/// frame again, an ack that does not advance too, a duplicate of an
/// earlier frame is dropped, and the far end's `SKIP` ends it with its
/// reason and no `STOP`.
#[test]
fn an_upload_sends_again_drops_echoes_and_ends_at_a_skip() {
    let now = Instant::now();
    let dir = scratch("upload-faults");
    let path = dir.join("a.txt");
    std::fs::write(&path, b"hello\n").expect("a file");
    let start = |z: &mut Zmodem| {
        output(z, TRIGGER_R, now);
        keys(z, format!("{}\r", path.display()).as_bytes(), now);
        output(z, &far(HELO), now);
    };
    // X1: no answer to DATA for the resend time; then the same bytes.
    let mut z = Zmodem::new();
    start(&mut z);
    let data = output(&mut z, &far(TAKE), now).server;
    assert_eq!(data, near(DATA));
    let resend = z.deadline().expect("a resend is due");
    assert!(resend <= now + Duration::from_secs(1), "the first resend is at 1 s");
    z.tick(resend);
    assert_eq!(step(&mut z, Vec::new(), resend).server, data, "X1: the same frame again");
    // X12: an echo of its own frame, or a repaint of an old one, is junk.
    assert!(output(&mut z, &far(TAKE), resend).server.is_empty(), "X12");
    // X2: an ack of 0 bytes asks for the frame again.
    let s = output(&mut z, &far("#ACKN:AAAAAAAAAAAAAAAAAAAAAA!ffef870b"), resend);
    assert_eq!(s.server, data, "X2");
    // X8: the far end skips the file.
    let mut z = Zmodem::new();
    start(&mut z);
    let s = output(&mut z, &far("#SKIP:ABFhLnR4dCBleGlzdHMgaGVyZQ!409966d8"), now);
    assert!(s.server.is_empty() && !z.busy(), "X8: no STOP answers a SKIP");
    assert!(s.screen.contains("tx: podssh tx on the server: a.txt exists here"), "X8: {:?}", s.screen);
}

/// The rows of version 2 at the session's watch. X13: a `KEPT` lost on
/// the path; the far end's `DONE` that comes again gets the same `KEPT`,
/// and never shows. X17: while a person answers whether a file goes over
/// one that is there, each `OFFR` that comes again gets `HOLD`, and the
/// answer after a minute still takes the file. X19: an upload whose `KEPT`
/// never comes ends unconfirmed after 20 s, with no `STOP`.
#[test]
fn version_2_holds_lingers_and_ends_unconfirmed() {
    let now = Instant::now();
    // X13.
    let dir = scratch("x13");
    let mut z = Zmodem::new();
    output(&mut z, TRIGGER_S, now);
    keys(&mut z, format!("{}\r", dir.display()).as_bytes(), now);
    for frame in [HELO, OFFR, DATA, DONE] {
        output(&mut z, &far(frame), now);
    }
    assert!(!z.busy(), "the download ended");
    let later = now + Duration::from_secs(2);
    let s = output(&mut z, &far(DONE), later);
    assert_eq!(s.server, near(KEPT), "X13: KEPT again");
    assert!(!s.screen.contains("#DONE:"), "X13: {:?}", s.screen);
    assert!(z.deadline().is_some(), "the verdict's end is a deadline");
    // X17.
    let dir = scratch("x17");
    std::fs::write(dir.join("a.txt"), b"kept here").expect("a file");
    let mut z = Zmodem::new();
    output(&mut z, TRIGGER_S, now);
    keys(&mut z, format!("{}\r", dir.display()).as_bytes(), now);
    output(&mut z, &far(HELO), now);
    let s = output(&mut z, &far(OFFR), now);
    assert!(s.screen.contains("exists. Replace it? [y/N]") && s.server.is_empty(), "{:?}", s.screen);
    for at in 1..=12u64 {
        let at = now + Duration::from_secs(5 * at);
        assert_eq!(output(&mut z, &far(OFFR), at).server, near(HOLD), "X17: HOLD");
    }
    let minute = now + Duration::from_secs(60);
    assert_eq!(keys(&mut z, b"y\r", minute).server, near(TAKE), "X17: the answer takes the file");
    // X19.
    let dir = scratch("x19");
    let path = dir.join("a.txt");
    std::fs::write(&path, b"hello\n").expect("a file");
    let mut z = Zmodem::new();
    output(&mut z, TRIGGER_R, now);
    keys(&mut z, format!("{}\r", path.display()).as_bytes(), now);
    output(&mut z, &far(HELO), now);
    output(&mut z, &far(TAKE), now);
    assert_eq!(output(&mut z, &far(ACKN), now).server, near(DONE));
    let (mut screen, mut sent) = (String::new(), Vec::new());
    let mut at = now;
    while z.busy() && at < now + Duration::from_secs(30) {
        at = z.deadline().expect("a wait").max(at);
        z.tick(at);
        let s = step(&mut z, Vec::new(), at);
        screen.push_str(&s.screen);
        sent.extend(s.server);
    }
    assert!(!z.busy() && at <= now + Duration::from_secs(20), "X19: the end at 20 s");
    let sent = String::from_utf8_lossy(&sent);
    assert!(!sent.contains("#STOP:"), "X19: no STOP: {sent:?}");
    assert!(screen.contains("sent a.txt (6 bytes); the server did not confirm that it kept it"), "{screen:?}");
}
