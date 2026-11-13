//! `podssh serve --stdio --pty line` (T-111) against OpenSSH's client with
//! `-tt`: serve is the line discipline, as on a host with no `/dev/ptmx`.
//! The keys come one after another, as typed: `sleep 30`, then Ctrl-C,
//! which must end the sleep and not the shell, then `echo AFTER-$?` and
//! `exit 9`, all within 15 s. Unix's; a host with no OpenSSH client says
//! that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serve_kit::{have_openssh, keygen, openssh_with, scratch};

/// The bound of the whole session, as the Prove of T-111 says.
const BOUND: Duration = Duration::from_secs(15);

#[test]
fn ctrl_c_through_openssh_ends_the_command_and_exit_9_ends_the_session() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let dir = scratch("line");
    keygen(&dir.0, &dir.0.join("id"));
    let serve = " --pty line --shell /bin/sh";
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", serve, &["-tt"], &[]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
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
    // A key at a time, as typed: the login, the prompt, then each line.
    for (pause, keys) in [(2000, &b"sleep 30\r"[..]), (1000, b"\x03"), (500, b"echo AFTER-$?\r"), (500, b"exit 9\r")] {
        std::thread::sleep(Duration::from_millis(pause));
        let _ = stdin.write_all(keys);
        let _ = stdin.flush();
    }
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > BOUND + Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ssh -tt did not end within {:?}", BOUND + Duration::from_secs(5));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    drop(stdin);
    let text = String::from_utf8_lossy(&rx.recv_timeout(BOUND).unwrap_or_default()).into_owned();
    assert!(text.contains("AFTER-130"), "Ctrl-C ended sleep, and the shell went on: {text:?}");
    assert_eq!(status.code(), Some(9), "{text:?}");
    assert!(took < BOUND, "the session took {took:?}: {text:?}");
}
