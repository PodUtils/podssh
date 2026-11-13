//! The stop of `podssh serve --stdio` (T-117) against OpenSSH's client: a
//! command that runs `sleep 100` through serve, then a SIGTERM to serve.
//! The client ends within 5 s with serve's reason (`podssh serve is
//! stopping`), serve exits 0, and the child is gone; a SIGHUP in between
//! reads the keys again and keeps the session. Unix's, as `serve_openssh.rs`;
//! a host with no OpenSSH client says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::io::Read;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serve_kit::{ends_within, have_openssh, keygen, number_in, openssh_proxy, runs, scratch, wrapped_serve, Scratch};

/// A scratch home with the key `id` (listed) made, or None where this host
/// has no OpenSSH client.
fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    Some(dir)
}

/// `child`'s exit code within `limit` and its stderr, or None when it ran
/// past the limit (it is killed then).
fn ended_within(mut child: Child, limit: Duration) -> (Option<i32>, Duration, String) {
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status.code();
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    let mut err = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut err);
    }
    (code, took, err)
}

fn signal(pid: i32, number: i32) {
    // SAFETY: kill has no memory effect.
    assert_eq!(unsafe { libc::kill(pid, number) }, 0, "signal {number} to serve {pid}");
}

#[test]
fn a_sigterm_ends_the_client_with_the_reason_and_leaves_no_child() {
    let Some(dir) = home("stop") else { return };
    let (home, key) = (&dir.0, dir.0.join("id"));
    let child_file = home.join("child.pid");
    let remote = format!("echo $$ > '{}'; exec sleep 100", child_file.display());
    let mut cmd = openssh_proxy(home, &key, "accept-new", &wrapped_serve(home), &[], &[&remote]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    let client = cmd.spawn().expect("ssh runs");
    let child = number_in(&child_file);
    let serve = number_in(&home.join("serve.pid"));
    assert!(runs(child), "the command runs");

    // A reload in between keeps the session.
    signal(serve, libc::SIGHUP);
    std::thread::sleep(Duration::from_millis(300));
    assert!(runs(serve) && runs(child), "SIGHUP stopped nothing");

    signal(serve, libc::SIGTERM);
    let (code, took, err) = ended_within(client, Duration::from_secs(10));
    assert!(code.is_some() && took < Duration::from_secs(5), "ssh ended after {took:?} ({code:?}): {err}");
    assert!(err.contains("podssh serve is stopping"), "the client says serve's reason: {err}");
    assert!(err.contains("SIGHUP: the authorized keys read again, 1 in all"), "{err}");
    assert_eq!(number_in(&home.join("serve.status")), 0, "a stop exits 0: {err}");
    assert!(ends_within(child, Duration::from_secs(5)), "sleep 100 runs on after the stop: {err}");
}
