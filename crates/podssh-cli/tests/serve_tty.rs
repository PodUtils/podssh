//! `podssh serve --stdio --pty notify` (T-776) against OpenSSH's client
//! with `-tt`: serve answers the program's tty calls by seccomp's user
//! notification, with no pty, as on a host with no `/dev/ptmx`. bash, as
//! the login shell, sees a tty: `test -t 0` and `stty size` answer, Ctrl-C
//! ends `sleep 30` with 130 and the shell goes on, less draws its screen
//! and reads its `q` from `/dev/tty`, vi takes `:q!`, top draws one frame,
//! and `exit 9` ends the session. The
//! keys come one after another, as typed. Linux's, on x86_64 and aarch64; a
//! host with no OpenSSH client, or whose kernel refuses the notification
//! (podssh doctor's line `pty notify`), says that the test did not run.

#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]

mod serve_kit;

use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serve_kit::{have_openssh, keygen, openssh_with, scratch};

/// The bound of the whole session.
const BOUND: Duration = Duration::from_secs(45);

/// The keys, each after its pause in ms, through `ssh -tt` to `serve`;
/// the session's output and its exit code.
fn session(serve: &str, keys: &[(u64, &[u8])]) -> (String, Option<i32>) {
    let dir = scratch("tty");
    keygen(&dir.0, &dir.0.join("id"));
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", serve, &["-tt"], &[]);
    cmd.env("TERM", "xterm").stdin(Stdio::piped()).stdout(Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn().expect("ssh runs");
    let mut out = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out.read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let mut stdin = child.stdin.take().expect("stdin");
    for (pause, bytes) in keys {
        std::thread::sleep(Duration::from_millis(*pause));
        let _ = stdin.write_all(bytes);
        let _ = stdin.flush();
    }
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > BOUND {
            let _ = child.kill();
            let _ = child.wait();
            break child.wait().expect("wait");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    let text = String::from_utf8_lossy(&rx.recv_timeout(BOUND).unwrap_or_default()).into_owned();
    (text, status.code())
}

/// Whether serve can answer tty calls on this host: serve's own probe,
/// which doctor's line `pty notify` also runs.
fn notify_here() -> bool {
    podssh_ssh::server::notify::probe().is_ok()
}

#[test]
fn bash_sees_a_tty_that_serve_answers_with_no_pty() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    if !notify_here() {
        eprintln!("did not run: this kernel refuses seccomp's user notification (podssh doctor: pty notify)");
        return;
    }
    let serve = " --pty notify --shell /bin/bash";
    let keys: &[(u64, &[u8])] = &[
        (2500, b"test -t 0 && echo TTY-YES-$(stty size | tr ' ' x)\r"),
        (800, b"sleep 30\r"),
        (1000, b"\x03"),
        (500, b"echo AFTER-$?\r"),
        (500, b"less /etc/os-release\r"),
        (1500, b"q"),
        (500, b"echo LESS-DONE-$?\r"),
        (500, b"vi -u NONE /etc/os-release\r"),
        (1500, b"\x1b:q!\r"),
        (500, b"echo VI-DONE-$?\r"),
        (500, b"top -n 1\r"),
        (2500, b"echo TOP-DONE-$?\r"),
        (500, b"exit 9\r"),
    ];
    let (text, code) = session(serve, keys);
    assert!(text.contains("TTY-YES-24x80"), "test -t 0 and stty size on the socket: {text:?}");
    assert!(text.contains("AFTER-130"), "Ctrl-C ended sleep, and the shell went on: {text:?}");
    assert!(text.contains("NAME="), "less drew the file: {text:?}");
    assert!(text.contains("LESS-DONE-0"), "less read its q from /dev/tty and ended: {text:?}");
    assert!(text.contains("VI-DONE-0"), "vi drew its screen and read :q!: {text:?}");
    assert!(text.contains("load average"), "top drew its screen: {text:?}");
    assert!(text.contains("TOP-DONE-0"), "top ended after one frame: {text:?}");
    assert_eq!(code, Some(9), "{text:?}");
}

#[test]
fn pty_names_notify_among_its_modes() {
    // `--pty notify` is a mode the CLI takes; a value it does not know is 64.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["serve", "--stdio", "--pty", "nonesuch", "--authorized-keys", "/nonexistent"])
        .stdin(Stdio::null())
        .output()
        .expect("serve runs");
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("auto, notify, line or no"));
}
