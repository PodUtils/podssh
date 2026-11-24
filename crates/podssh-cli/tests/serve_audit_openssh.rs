//! The audit log of `podssh serve --stdio` (T-116) against software that
//! podssh did not write: OpenSSH's client, with serve as its ProxyCommand
//! and `--audit-log FILE`. `echo SECRET-MARKER` leaves the login and its
//! exit status in the file, and its words only with `--audit-commands`;
//! two serve processes append one chain, which `--audit-verify` passes,
//! and an edited line fails it (65). Unix's, as `serve_openssh.rs`; a host
//! with no OpenSSH client says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::path::Path;
use std::process::Command;

use serve_kit::{finish, have_openssh, keygen, openssh_with, scratch, Scratch, BIN};

const MARKER: &str = "SECRET-MARKER";

fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    Some(dir)
}

/// `podssh serve --audit-verify FILE`: its code and its stdout.
fn verify(log: &Path) -> (Option<i32>, String) {
    let out = Command::new(BIN).args(["serve", "--audit-verify"]).arg(log).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn a_session_is_recorded_and_its_words_only_when_asked() {
    for (flags, count) in [("", 0), (" --audit-commands", 1)] {
        let Some(dir) = home("audit") else { return };
        let log = dir.0.join("audit.log");
        let serve = format!(" --audit-log '{}'{flags}", log.display());
        let ssh = || openssh_with(&dir.0, &dir.0.join("id"), "accept-new", &serve, &[], &[&format!("echo {MARKER}")]);
        let (code, err) = finish(ssh());
        assert_eq!(code, Some(0), "{err}");
        let text = std::fs::read_to_string(&log).unwrap();
        for word in ["\"serve.start\"", "\"serve.auth.accepted\"", "\"exit_status\":0", "\"serve.stop\""] {
            assert!(text.contains(word), "{word}: {text}");
        }
        assert_eq!(text.matches(MARKER).count(), count, "flags {flags:?}: {text}");
        // A second serve process appends to the same chain.
        let (code, err) = finish(ssh());
        assert_eq!(code, Some(0), "{err}");
        let (code, said) = verify(&log);
        assert_eq!(code, Some(0), "{said}");
        assert!(said.contains("the chain holds") && said.contains("SHA-256"), "{said}");
    }
}

#[test]
fn an_edited_line_fails_the_check() {
    let Some(dir) = home("audit-edit") else { return };
    let log = dir.0.join("audit.log");
    let serve = format!(" --audit-log '{}'", log.display());
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", &serve, &[], &["exit 3"]));
    assert_eq!(code, Some(3), "{err}");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("\"exit_status\":3"), "{text}");
    std::fs::write(&log, text.replace("\"exit_status\":3", "\"exit_status\":0")).unwrap();
    let (code, said) = verify(&log);
    assert_eq!(code, Some(65), "{said}");
    assert!(said.contains("the chain breaks"), "{said}");
}
