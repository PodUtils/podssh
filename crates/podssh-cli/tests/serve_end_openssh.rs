//! The lines of `podssh serve --stdio` at a client's normal end (T-869),
//! against software that podssh did not write: OpenSSH's client, with serve
//! as its ProxyCommand and no wrapper, so that OpenSSH's own SIGHUP at its
//! exit reaches serve, as it does in use. Each end, a command that ran, a
//! pty that a key's `no-pty` refused, a forward that `restrict` or
//! `--no-forwarding` refused (OpenSSH then closes with no DISCONNECT), says
//! no reload and no failure: the SIGHUP that comes with the end of the
//! input is the client's end. An operator's SIGHUP on a live session still
//! reloads (`serve_lifecycle_openssh.rs`). Unix's, as `serve_openssh.rs`; a
//! host with no OpenSSH client says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use serve_kit::{finish, have_openssh, keygen, openssh_with, scratch, Scratch};

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
    if options.is_empty() {
        return Some(dir);
    }
    let public = dir.0.join("id.pub");
    let line = std::fs::read_to_string(&public).unwrap();
    std::fs::write(&public, format!("{options} {}", line.trim_start())).unwrap();
    Some(dir)
}

/// A port of this host that nothing listens on: bound, then let go.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The words that no normal end may say on serve's stderr, which OpenSSH's
/// stderr carries (the ProxyCommand's is the client's).
const NEVER: [&str; 4] = ["SIGHUP", "the SSH connection failed", "Broken pipe", "early eof"];

/// One table: each normal end, the key's options, serve's flags, the
/// client's options and command, its exit code, and words that show the
/// case ran as meant.
#[test]
fn a_client_s_normal_end_says_no_reload_and_no_failure() {
    let closed = format!("127.0.0.1:{}", closed_port());
    type Case<'a> = (&'a str, &'a str, &'a str, Vec<&'a str>, Vec<&'a str>, i32, &'a str);
    #[rustfmt::skip]
    let cases: Vec<Case> = vec![
        ("a command", "", "", vec![], vec!["echo ran"], 0, ""),
        // OpenSSH ends a session whose forced pty was refused (255), as serve_options_openssh pins.
        ("a refused pty", "no-pty", "", vec!["-tt"], vec!["echo ran"], 255, "PTY allocation request failed"),
        ("a forward refused by restrict", "restrict", "", vec!["-W", closed.as_str()], vec![], 255, "no-port-forwarding"),
        ("a forward refused by the flag", "", " --no-forwarding", vec!["-W", closed.as_str()], vec![], 255, "--no-forwarding"),
    ];
    for (tag, (case, options, serve, client, remote, code, shown)) in cases.iter().enumerate() {
        let Some(dir) = home(&format!("end-{tag}"), options) else { return };
        let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", serve, client, remote);
        let (got, err) = finish(cmd);
        assert_eq!(got, Some(*code), "{case}: {err}");
        assert!(err.contains(shown), "{case}: ran as meant: {err}");
        for never in NEVER {
            let line = err.lines().find(|l| l.contains("podssh serve") && l.contains(never));
            assert!(line.is_none(), "{case}: {never:?} at a normal end: {err}");
        }
    }
}
