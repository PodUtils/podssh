//! The frames of the far end's screen from end to end (T-303): `podssh ssh
//! -tt --frames` in a pty of Linux, through the stand-in relay's link of
//! 150 ms each way and 64 KiB/s (T-203: `link:150:65536:1500000:0:1`, a
//! round trip of 300 ms), to `podssh serve --listen` on the loopback, whose
//! shell floods the terminal. The terminal oracle (T-200's model, `vt100`)
//! reads each byte that podssh writes to its terminal.
//!
//! Pass: with `--frames`, the prompt after Ctrl-C shows within three round
//! trips, and the session ends with the shell's status. The control: with
//! no `--frames`, the same Ctrl-C shows its prompt only after the bytes of
//! the flood that were on their way, later than three round trips. The
//! same bar holds for a client of a control master (`-M -N -S CTL`), whose
//! master draws the frames on the client's terminal. And a
//! session with `--frames-scroll --record`: the recording holds what the terminal
//! was drawn with, and `podssh play` of it gives the terminal's screen. A
//! host with no Python or openssl (the stand-in relay) or no pty says that
//! the test did not run:
//!
//! ```sh
//! cargo test -p podssh-cli --test frames_e2e
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
/// The link of the stand-in relay, each way: 150 ms, 64 KiB/s, a queue of
/// 1.5 MB, no loss.
const LINK: &str = "link:150:65536:1500000:0:1";
/// The bar of the entry: three round trips of 300 ms.
const BAR: Duration = Duration::from_millis(900);
/// A bound on each wait for the far end; the control's flood takes long.
const LIMIT: Duration = Duration::from_secs(180);
/// The prompt of the far end's shell: set by the command, never typed, so
/// no echo of a typed line is it.
const PROMPT: &str = "FRAMEP>";
const FAR: &str = "exec env PS1='FRAMEP> ' ENV= /bin/sh -i";
const FLOOD: &[u8] = b"i=0; while :; do i=$((i+1)); echo \"flood $i of a loop that prints for ever\"; done\r";

/// The row of the cursor on a terminal that read `bytes`, with no
/// trailing blank, and the whole screen's text.
fn shown(bytes: &[u8]) -> (String, String) {
    let size = |n: u16| std::num::NonZeroU16::new(n).unwrap();
    let mut model = vt100::Parser::new(size(ROWS), size(COLS), 0);
    model.process(bytes);
    let screen = model.screen();
    let (row, _) = screen.cursor_position();
    let line = screen.rows(0, COLS).nth(usize::from(row)).unwrap_or_default();
    (line.trim_end().to_string(), screen.contents())
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
    let cell = match Cell::fake_relay_mode(&session, LINK, "the stand-in relay, 150 ms each way and 64 KiB/s") {
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

/// `podssh ssh -tt` in a pty, through the cell to serve's port, with
/// `extra` options, running [`FAR`].
fn client(session: &Session, cell: &Cell, port: u16, extra: &[&str]) -> Pty {
    let mut args = cell.args.clone();
    // The cell's port is the test's own SSH server: serve's in its place.
    if let Some(at) = args.iter().position(|a| a == "-p") {
        args[at + 1] = port.to_string();
    }
    let destination = args.pop().expect("the cell's destination");
    args.extend(["-tt", "-i"].map(String::from));
    args.push(session.home.join("id").display().to_string());
    args.extend(extra.iter().map(|s| s.to_string()));
    args.push(destination);
    args.push(FAR.to_string());
    let mut cmd = without_proxy(session.command(&args));
    cmd.env("TERM", "xterm");
    Pty::start(cmd, ROWS, COLS)
}

/// Wait until the terminal shows what `done` takes (the cursor's row and
/// the screen's text), at most `limit`: how long after `from`.
fn until(term: &Pty, from: Instant, limit: Duration, what: &str, done: impl Fn(&str, &str) -> bool) -> Duration {
    let deadline = Instant::now() + limit;
    loop {
        let (row, text) = shown(&term.bytes());
        if done(&row, &text) {
            return from.elapsed();
        }
        assert!(Instant::now() < deadline, "{what}: not within {limit:?}; the cursor's row is {row:?} of {text:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The session to its flood, then Ctrl-C: the time from the key to the
/// prompt, on the terminal.
fn interrupt(term: &mut Pty) -> Duration {
    until(term, Instant::now(), LIMIT, "the first prompt", |row, _| row == PROMPT);
    term.send(FLOOD);
    until(term, Instant::now(), LIMIT, "the flood", |row, text| row != PROMPT && text.contains("flood "));
    // The flood fills what the link holds, as a long listing does.
    std::thread::sleep(Duration::from_secs(2));
    let sent = Instant::now();
    term.send(&[0x03]);
    until(term, sent, LIMIT, "the prompt after Ctrl-C", |row, text| row == PROMPT && text.contains("^C"))
}

#[test]
fn with_frames_ctrl_c_shows_the_prompt_within_three_round_trips() {
    let Some((session, cell, port)) = setup("frames-e2e") else { return };
    let mut term = client(&session, &cell, port, &["--frames"]);
    let after = interrupt(&mut term);
    eprintln!("--frames: Ctrl-C to the prompt in {} ms", after.as_millis());
    assert!(after < BAR, "the prompt showed {after:?} after Ctrl-C, over three round trips ({BAR:?})");
    assert!(!term.text().contains("sends no frames"), "the far end took the ask: {:?}", term.text());
    term.send(b"exit 5\r");
    assert_eq!(term.wait(LIMIT), Some(5), "the shell's status: {:?}", term.text());
}

/// A control master `-M -N -S CTL` through the cell to serve's port, kept
/// until the session ends; returned once its socket is there. A client
/// that comes before the master's login waits in the hello.
fn master(session: &Session, cell: &Cell, port: u16, ctl: &Path) {
    let mut args = cell.args.clone();
    if let Some(at) = args.iter().position(|a| a == "-p") {
        args[at + 1] = port.to_string();
    }
    let destination = args.pop().expect("the cell's destination");
    args.extend(["-M", "-N", "-S"].map(String::from));
    args.push(ctl.display().to_string());
    args.push("-i".to_string());
    args.push(session.home.join("id").display().to_string());
    args.push(destination);
    let mut cmd = without_proxy(session.command(&args));
    cmd.env_remove("PODSSH_LISTEN").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    session.keep(cmd.spawn().expect("the master starts"));
    let deadline = Instant::now() + LIMIT;
    while !ctl.exists() {
        assert!(Instant::now() < deadline, "no control socket at {} within {LIMIT:?}", ctl.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Through a control master of podssh's (T-303, item h): the master asks
/// serve for the frames and draws them on the client's terminal, so
/// Ctrl-C shows the prompt within three round trips, as with no master.
#[test]
fn through_a_control_master_ctrl_c_shows_the_prompt_within_three_round_trips() {
    let Some((session, cell, port)) = setup("frames-e2e-master") else { return };
    let ctl = session.home.join("ctl");
    master(&session, &cell, port, &ctl);
    let mut term = client(&session, &cell, port, &["-S", ctl.to_str().expect("a path of text"), "--frames"]);
    let after = interrupt(&mut term);
    eprintln!("--frames through a master: Ctrl-C to the prompt in {} ms", after.as_millis());
    assert!(after < BAR, "the prompt showed {after:?} after Ctrl-C, over three round trips ({BAR:?})");
    let text = term.text();
    assert!(!text.contains("sends no frames") && !text.contains("does not carry them"), "frames came: {text:?}");
    term.send(b"exit 5\r");
    assert_eq!(term.wait(LIMIT), Some(5), "the shell's status through the master: {:?}", term.text());
}

/// The control: the flood and the link were there. Without `--frames` the
/// prompt comes after the bytes that were on their way.
#[test]
fn without_frames_the_prompt_waits_for_the_bytes_of_the_flood() {
    let Some((session, cell, port)) = setup("frames-e2e-off") else { return };
    let mut term = client(&session, &cell, port, &[]);
    let after = interrupt(&mut term);
    eprintln!("no --frames: Ctrl-C to the prompt in {} ms", after.as_millis());
    assert!(after >= BAR, "the prompt showed {after:?} after Ctrl-C: the flood or the link was not there");
    term.send(b"exit 5\r");
    assert_eq!(term.wait(LIMIT), Some(5), "the shell's status: {:?}", term.text());
}

/// `--record` of a framed session: the far end's bytes never arrive, so
/// the recording holds the frames' drawing, which is terminal output, and
/// `podssh play` of it gives the screen that the terminal showed. Sixty
/// lines on a screen of 24 rows: the lines that left its top are drawn
/// into the recording too.
#[test]
fn a_framed_session_recorded_plays_as_its_terminal_showed_it() {
    let Some((session, cell, port)) = setup("frames-e2e-record") else { return };
    let file = session.home.join("framed.cast");
    let record = file.display().to_string();
    let mut term = client(&session, &cell, port, &["--frames-scroll", "--record", &record]);
    until(&term, Instant::now(), LIMIT, "the first prompt", |row, _| row == PROMPT);
    term.send(b"i=0; while [ $i -lt 60 ]; do i=$((i+1)); echo \"line $i\"; done; echo MARK-$((6*7))\r");
    until(&term, Instant::now(), LIMIT, "the mark", |row, text| row == PROMPT && text.contains("MARK-42"));
    // The screen is still, and each draw is in the file: it is flushed at
    // each event, before the terminal gets it.
    std::thread::sleep(Duration::from_secs(1));
    let (_, showed) = shown(&term.bytes());
    let played = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["play", "--idle-limit", "0.001"])
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .expect("podssh play runs");
    assert!(played.status.success(), "podssh play: {}", String::from_utf8_lossy(&played.stderr));
    let (_, again) = shown(&played.stdout);
    assert!(again.contains("MARK-42") && again.contains("line 60"), "the recording's last screen: {again:?}");
    assert_eq!(again, showed, "the recording plays as the terminal showed it");
    term.send(b"exit 5\r");
    assert_eq!(term.wait(LIMIT), Some(5), "the shell's status: {:?}", term.text());
}
