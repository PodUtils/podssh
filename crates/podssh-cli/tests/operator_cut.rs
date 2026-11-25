//! An operator whose end-to-end channel is cut before its end (T-753): the
//! node's target resets its connection after part of the answer, the node's
//! carry ends, and the operator must not read that as a clean end. Its exit
//! is 69, with pod-e2e's words that the last bytes can be missing. The node
//! runs on a stdio carrier, so no relay and nothing off the loopback.

#![cfg(unix)]

mod live_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use live_harness::{scratch, LIMIT};

const BIN: &str = env!("CARGO_BIN_EXE_podssh");

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A target that reads what comes, answers `part` bytes, then resets its
/// connection (SO_LINGER of 0): its peer's read fails, with no end.
fn resetting(part: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                let _ = conn.write_all(&vec![b'x'; part]);
                std::thread::sleep(Duration::from_millis(200));
                let linger = libc::linger { l_onoff: 1, l_linger: 0 };
                // SAFETY: a plain option of this test's own socket.
                unsafe {
                    libc::setsockopt(
                        conn.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&linger as *const libc::linger).cast(),
                        std::mem::size_of::<libc::linger>() as libc::socklen_t,
                    );
                }
                drop(conn);
            });
        }
    });
    port
}

#[test]
fn a_target_that_resets_ends_the_operator_with_69_and_says_the_cut() {
    let home = scratch("operator-cut");
    let _scratch = Scratch(home.clone());
    let target = format!("127.0.0.1:{}", resetting(1000));
    assert!(!BIN.contains('\''), "a path that the words cannot carry");
    let carrier = format!("exec:'{BIN}' node --carrier stdio box {target}");
    let mut child = live_harness::command(&home, &["operator", "--carrier", &carrier, "box"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the operator runs");
    // Its stdin stays open, so only the target's reset ends the session.
    let mut stdin = child.stdin.take().expect("stdin");
    let _ = stdin.write_all(b"a question\n");
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let reading = std::thread::spawn(move || {
        let (mut o, mut e) = (Vec::new(), String::new());
        let _ = out.read_to_end(&mut o);
        let _ = err.read_to_string(&mut e);
        (o, e)
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the operator did not end within {LIMIT:?} of its target's reset");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(stdin);
    let (out, err) = reading.join().unwrap();
    assert_eq!(status.code(), Some(69), "{} bytes came; {err}", out.len());
    assert!(err.contains("the last bytes can be missing"), "{err}");
}
