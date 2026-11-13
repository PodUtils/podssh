//! The options of a key line of `podssh serve --stdio` (T-114) against
//! software that podssh did not write: OpenSSH's client, with the server as
//! its ProxyCommand and the key's line in `--authorized-keys` with options.
//! A forced command runs in place of the asked one, with
//! `SSH_ORIGINAL_COMMAND`; `no-pty` refuses `-tt`; `permitopen=` lets one
//! `-W` target through and refuses another, named; `restrict` refuses a
//! `-W`; a past `expiry-time=` refuses the login, and serve's stderr says
//! why. Unix's, as `serve_openssh.rs`; a host with no OpenSSH client says
//! that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::process::Stdio;
use std::thread::JoinHandle;

use serve_kit::{finish, have_openssh, keygen, openssh_with, run, scratch, Scratch, LIMIT};

/// A scratch home with the key `id` made, and its line in `id.pub` (the
/// file that serve reads) after `options`; None where this host has no
/// OpenSSH client.
fn home(tag: &str, options: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    let public = dir.0.join("id.pub");
    let line = std::fs::read_to_string(&public).unwrap();
    std::fs::write(&public, format!("{options} {}", line.trim_start())).unwrap();
    Some(dir)
}

/// A listener of the test that echoes one connection until its EOF: its
/// port, and the count it echoed.
fn echo_once() -> (u16, JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let Ok((mut tcp, _)) = listener.accept() else { return 0 };
        tcp.set_read_timeout(Some(LIMIT)).unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut echoed = 0;
        while let Ok(n @ 1..) = tcp.read(&mut buf) {
            if tcp.write_all(&buf[..n]).is_err() {
                break;
            }
            echoed += n;
        }
        let _ = tcp.shutdown(Shutdown::Write);
        echoed
    });
    (port, task)
}

#[test]
fn a_forced_command_runs_in_place_of_the_asked_one() {
    let options = r#"command="echo forced; echo \"orig=$SSH_ORIGINAL_COMMAND\"""#;
    let Some(dir) = home("opt-forced", options) else { return };
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &[], &["echo asked; exit 3"]);
    cmd.stdout(Stdio::piped());
    let (code, out, err) = run(cmd, None);
    assert_eq!(code, Some(0), "the forced command's status, not the asked one's: {err}");
    assert_eq!(String::from_utf8_lossy(&out), "forced\norig=echo asked; exit 3\n", "{err}");
}

#[test]
fn no_pty_refuses_a_forced_pty() {
    let Some(dir) = home("opt-nopty", "no-pty") else { return };
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-tt"], &["echo ran"]);
    cmd.stdout(Stdio::piped());
    let (code, out, err) = run(cmd, None);
    assert!(err.contains("PTY allocation request failed"), "{err}");
    assert_eq!(code, Some(255), "OpenSSH ends a session whose forced pty was refused: {err}");
    assert!(!String::from_utf8_lossy(&out).contains("ran"), "{err}");
    // serve says the rule (its stderr is the ProxyCommand's, and ssh's).
    assert!(err.contains("no-pty"), "{err}");
    // Without -tt the command runs.
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &[], &["exit 5"]));
    assert_eq!(code, Some(5), "{err}");
}

#[test]
fn permitopen_lets_one_target_through_and_refuses_another() {
    let (port, echo) = echo_once();
    let (other, _unused) = echo_once();
    let Some(dir) = home("opt-open", &format!(r#"permitopen="127.0.0.1:{port}""#)) else { return };
    let target = format!("127.0.0.1:{port}");
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-W", &target], &[]);
    let sent = b"through the one target".to_vec();
    let (code, back, err) = run(cmd, Some(sent.clone()));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(back, sent, "{err}");
    assert_eq!(echo.join().unwrap(), sent.len());
    let refused = format!("127.0.0.1:{other}");
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-W", &refused], &[]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("administratively prohibited"), "{err}");
    assert!(err.contains("permitopen") && err.contains(&refused), "the rule and the target named: {err}");
    // Wake the listener that was never dialed, so its thread ends.
    let _ = std::net::TcpStream::connect(("127.0.0.1", other));
}

#[test]
fn restrict_refuses_a_forward() {
    let (port, _echo) = echo_once();
    let Some(dir) = home("opt-restrict", "restrict") else { return };
    let target = format!("127.0.0.1:{port}");
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-W", &target], &[]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("no-port-forwarding"), "{err}");
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    // A command still runs.
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &[], &["exit 4"]));
    assert_eq!(code, Some(4), "{err}");
}

#[test]
fn a_past_expiry_time_refuses_the_login() {
    let Some(dir) = home("opt-expired", r#"expiry-time="20200101Z""#) else { return };
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &[], &["true"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("Permission denied (publickey)"), "{err}");
    assert!(err.contains("expiry-time"), "serve says why: {err}");
}
