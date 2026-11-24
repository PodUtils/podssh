//! Local echo from end to end (T-896): `podssh ssh -t --predict` in a pty
//! of Linux, through the stand-in relay's `delay:150` (T-203: each byte
//! 150 ms late each way, a round trip of 300 ms), to `podssh serve
//! --listen` on the loopback, whose command reads a line, then a password
//! with no echo. The terminal oracle (T-200's model, `vt100`) reads each
//! byte that podssh writes to its terminal.
//!
//! Pass: once the far end echoed the first key of the line, each key typed
//! after it shows on the terminal, underlined, sooner than its echo can
//! come back; once the echo came, the line is the far end's, underlined
//! nowhere. At the password's question no typed key shows, in any byte that
//! podssh writes, and the far end reads each one. The control: without
//! `--predict`, the same keys show only after the round trip. A host with
//! no Python or openssl (the stand-in relay) or no pty says that the test
//! did not run:
//!
//! ```sh
//! cargo test -p podssh-cli --test predict_e2e
//! ```

#![cfg(target_os = "linux")]

mod pty_harness;
mod ssh_harness;
mod throughput_harness;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pty_harness::Pty;
use throughput_harness::{lines_of, wait_for, without_proxy, Cell, Session};

const ROWS: u16 = 24;
const COLS: u16 = 80;
/// Each byte's delay at the stand-in relay, each way.
const DELAY: &str = "delay:150";
/// The least time in which a key's echo can come back: two delays, less a
/// margin for the clock of the test. A key on the terminal sooner is a guess.
const ECHO_SOONEST: Duration = Duration::from_millis(250);
/// A bound on each wait for the far end.
const LIMIT: Duration = Duration::from_secs(60);
/// The far end: a line read with the kernel's echo, then a password read
/// with none, and the length of what it read.
const FAR: &str = "printf 'line> '; read a; printf 'GOT[%s]\\n' \"$a\"; stty -echo; printf 'secret> '; read p; \
                   stty echo; printf '\\nLEN[%s]\\n' \"${#p}\"; printf 'end> '; read z";
/// The password's keys: none of them is in a sequence that podssh draws
/// with (digits, `[`, `;`, `C`, `D`, `X`, `m`), so any of them in podssh's
/// bytes is the key itself.
const SECRET: &[u8] = b"qvwy";

/// The model of the terminal after `bytes`.
fn screen(bytes: &[u8]) -> vt100::Parser {
    let size = |n: u16| std::num::NonZeroU16::new(n).unwrap();
    let mut model = vt100::Parser::new(size(ROWS), size(COLS), 0);
    model.process(bytes);
    model
}

/// The row of the cursor: its text, and which of its cells are underlined.
fn cursor_row(bytes: &[u8]) -> (String, Vec<bool>) {
    let model = screen(bytes);
    let screen = model.screen();
    let (row, _) = screen.cursor_position();
    let cells: Vec<_> = (0..COLS).filter_map(|col| screen.cell(row, col)).collect();
    let text: String = cells.iter().map(|c| if c.has_contents() { c.contents() } else { " " }).collect();
    (text.trim_end().to_string(), cells.iter().map(|c| c.underline()).collect())
}

/// `podssh serve --listen` on a loopback port, with the scratch key listed
/// and `/bin/sh` as its shell; the port that its line names.
fn serve(session: &Session) -> Result<u16, String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["serve", "--listen", "127.0.0.1:0", "--shell", "/bin/sh", "--authorized-keys"])
        .arg(session.home.join("id.pub"))
        .env("HOME", &session.home)
        .env("XDG_CACHE_HOME", session.home.join("cache"))
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child: Child = cmd.spawn().map_err(|e| format!("podssh serve: {e}"))?;
    let lines = lines_of(&mut child);
    session.keep(child);
    let line = wait_for(&lines, "listening on 127.0.0.1:")?;
    let rest = line.split("listening on 127.0.0.1:").nth(1).unwrap_or_default();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().map_err(|_| format!("no port in serve's line: {line}"))
}

/// A throwaway key at `id` in the session's home.
fn keygen(home: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(home.join("id"))
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .expect("podssh keygen runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// The session, the stand-in relay's cell and serve's port; None, with a
/// line, where this host cannot run them.
fn setup(tag: &str) -> Option<(Session, Cell, u16)> {
    if let Err(why) = podssh_ssh::server::pty::open() {
        eprintln!("did not run: no pty here, for serve: {why}");
        return None;
    }
    let session = Session::start(tag);
    let cell = match Cell::fake_relay_mode(&session, DELAY, "the stand-in relay, 150 ms each way") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    keygen(&session.home);
    let port = serve(&session).unwrap_or_else(|why| panic!("podssh serve: {why}"));
    Some((session, cell, port))
}

/// `podssh ssh -t` in a pty, through the cell to serve's port, with
/// `extra` options, running [`FAR`].
fn client(session: &Session, cell: &Cell, port: u16, extra: &[&str]) -> Pty {
    let mut args = cell.args.clone();
    // The cell's port is the test's own SSH server: serve's in its place.
    if let Some(at) = args.iter().position(|a| a == "-p") {
        args[at + 1] = port.to_string();
    }
    let destination = args.pop().expect("the cell's destination");
    args.extend(["-t", "-i"].map(String::from));
    args.push(session.home.join("id").display().to_string());
    args.extend(extra.iter().map(|s| s.to_string()));
    args.push(destination);
    args.push(FAR.to_string());
    let mut cmd = without_proxy(session.command(&args));
    cmd.env("TERM", "xterm");
    Pty::start(cmd, ROWS, COLS)
}

/// Type `keys` one at a time, as a person does: when the last one went.
fn type_keys(term: &mut Pty, keys: &[u8]) -> Instant {
    let mut last = Instant::now();
    for key in keys {
        term.send(&[*key]);
        last = Instant::now();
        std::thread::sleep(Duration::from_millis(30));
    }
    last
}

/// Wait until the cursor's row is `want`: how long after `from`, and
/// which cells were underlined then.
fn row_shows(term: &Pty, want: &str, from: Instant) -> (Duration, Vec<bool>) {
    let deadline = Instant::now() + LIMIT;
    loop {
        let (text, underlined) = cursor_row(&term.bytes());
        if text == want {
            return (from.elapsed(), underlined);
        }
        assert!(Instant::now() < deadline, "the row is {text:?}, not {want:?}: {:?}", term.text());
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The far end's first key of the line, typed and echoed: from then on the
/// epoch is confirmed (`docs/terminal.md`, "When a guess shows").
fn first_key(term: &mut Pty) {
    assert!(term.expect("line> ", LIMIT), "no question: {:?}", term.text());
    // Its report, with the pty's flags, follows the question.
    std::thread::sleep(Duration::from_millis(500));
    let typed = type_keys(term, b"h");
    row_shows(term, "line> h", typed);
    // The report of the key, after its echo, confirms the guess.
    std::thread::sleep(Duration::from_millis(800));
}

#[test]
fn typed_letters_show_before_the_echo_and_a_password_never_shows() {
    let Some((session, cell, port)) = setup("predict-e2e") else { return };
    let mut term = client(&session, &cell, port, &["--predict"]);
    first_key(&mut term);

    // Each key after the first shows sooner than any echo, underlined.
    let typed = type_keys(&mut term, b"ello");
    let (after, underlined) = row_shows(&term, "line> hello", typed);
    assert!(after < ECHO_SOONEST, "the last key showed {after:?} after it was typed: no guess");
    let guessed = &underlined["line> h".len().."line> hello".len()];
    assert!(guessed.iter().all(|u| *u), "the guesses are underlined: {underlined:?}");
    // Once the echo came, the row is the far end's: no underline is left.
    std::thread::sleep(Duration::from_secs(1));
    let (text, underlined) = cursor_row(&term.bytes());
    assert_eq!(text, "line> hello", "{:?}", term.text());
    assert!(underlined.iter().all(|u| !*u), "a guess stayed on the row: {underlined:?}");
    term.send(b"\r");
    assert!(term.expect("GOT[hello]", LIMIT), "the far end read the line: {:?}", term.text());

    // The password: a line with no echo. No key shows, not even for a moment.
    assert!(term.expect("secret> ", LIMIT), "no password's question: {:?}", term.text());
    let before = term.bytes().len();
    std::thread::sleep(Duration::from_millis(500));
    type_keys(&mut term, SECRET);
    let watch_until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < watch_until {
        let bytes = term.bytes();
        let shown: Vec<u8> = bytes[before..].iter().copied().filter(|b| SECRET.contains(b)).collect();
        assert!(shown.is_empty(), "a key of the password showed: {:?}", String::from_utf8_lossy(&bytes[before..]));
        assert_eq!(cursor_row(&bytes).0, "secret>", "the row holds the question alone");
        std::thread::sleep(Duration::from_millis(5));
    }
    term.send(b"\r");
    assert!(term.expect("LEN[4]", LIMIT), "the far end read each key: {:?}", term.text());
    assert!(term.expect("end> ", LIMIT), "{:?}", term.text());
    term.send(b"\r");
    assert_eq!(term.wait(LIMIT), Some(0), "podssh's code: {:?}", term.text());
}

/// The control: the delay was there. Without `--predict` the same keys
/// show only once their echo came back, and nothing is underlined.
#[test]
fn without_predict_a_key_shows_only_after_the_round_trip() {
    let Some((session, cell, port)) = setup("predict-e2e-off") else { return };
    let mut term = client(&session, &cell, port, &[]);
    first_key(&mut term);
    let typed = type_keys(&mut term, b"ello");
    let (after, underlined) = row_shows(&term, "line> hello", typed);
    assert!(after >= ECHO_SOONEST, "the last key showed {after:?} after it was typed: the delay was not there");
    assert!(underlined.iter().all(|u| !*u), "no guess with no --predict: {underlined:?}");
    term.send(b"\r");
    assert!(term.expect("secret> ", LIMIT), "{:?}", term.text());
    term.send(b"x\r");
    assert!(term.expect("end> ", LIMIT), "{:?}", term.text());
    term.send(b"\r");
    assert_eq!(term.wait(LIMIT), Some(0), "podssh's code: {:?}", term.text());
}
