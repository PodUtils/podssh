//! The algorithms of `podssh serve --stdio` (T-841), and the reply of each
//! refusal, against software that podssh did not write: OpenSSH's client,
//! with the server as its ProxyCommand.
//!
//! Each key exchange, cipher and MAC that this host's OpenSSH knows
//! (`ssh -Q`) is offered alone: a name of serve's stated set
//! (`podssh_ssh::server::algorithms`) logs in, and each other ends with
//! OpenSSH's `no matching ... found`, whose `Their offer:` is the set,
//! name for name. A host certificate, which serve never holds, is refused
//! the same way.
//!
//! The table [`REPLIES`] is what each refusal sends, with the request that
//! causes it and OpenSSH's words for it; each row that a client of OpenSSH
//! can cause runs here. Unix's, as `serve_openssh.rs`; a host with no
//! OpenSSH client says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::process::{Command, Stdio};

use podssh_ssh::server::algorithms;
use serve_kit::{finish, have_openssh, keygen, openssh_with, scratch, Scratch};

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

/// What each refusal of serve sends, the request that causes it, and what
/// OpenSSH's client says of it. `None` in the last column: no request of
/// OpenSSH's client causes it, and the row names where it is pinned.
#[rustfmt::skip]
const REPLIES: &[(&str, &str, Option<&str>)] = &[
    ("USERAUTH_FAILURE", "a key that no line lists, or that its line refuses now", Some("Permission denied (publickey)")),
    ("CHANNEL_FAILURE", "a channel request that serve does not serve: a subsystem other than sftp", Some("subsystem request failed")),
    ("REQUEST_FAILURE", "a global request that serve does not serve: tcpip-forward (-R)", Some("remote port forwarding failed for listen port")),
    // `serve_forward_openssh.rs`: `open failed: administratively prohibited`.
    ("CHANNEL_OPEN_FAILURE", "a forward that --no-forwarding or a key's rule refuses", None),
    // `serve_lifecycle_openssh.rs`: `Received disconnect ... podssh serve is stopping`.
    ("DISCONNECT", "a stop (SIGTERM, SIGINT); a key that a reload removed, with --revoke-ends-sessions (T-842)", None),
    // russh's server reads a message that it does not know and answers
    // nothing; no client of OpenSSH sends one.
    ("UNIMPLEMENTED", "never sent: an unknown message is passed over", None),
];

/// The lists of the handshake that OpenSSH's client takes by name: its
/// keyword, its query of `ssh -Q`, OpenSSH's word in `no matching ... found`,
/// and serve's names.
fn lists() -> Vec<(&'static str, &'static str, &'static str, Vec<String>)> {
    vec![
        ("KexAlgorithms", "kex", "key exchange method", algorithms::kex_names()),
        ("Ciphers", "cipher", "cipher", algorithms::names(algorithms::CIPHERS)),
        ("MACs", "mac", "MAC", algorithms::names(algorithms::MACS)),
    ]
}

/// The names that this host's OpenSSH knows of `query` (`ssh -Q`).
fn openssh_knows(query: &str) -> Vec<String> {
    let out = Command::new("ssh").args(["-Q", query]).stdin(Stdio::null()).output().expect("ssh -Q runs");
    assert!(out.status.success(), "ssh -Q {query}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

/// The names of OpenSSH's `Their offer:` in `err`, without the extensions
/// that ride in a list of key exchanges.
fn their_offer(err: &str) -> Option<Vec<String>> {
    let (_, rest) = err.split_once("Their offer: ")?;
    let list = rest.lines().next()?.trim();
    let extension = |n: &&str| n.starts_with("ext-info-") || n.starts_with("kex-strict-");
    Some(list.split(',').filter(|n| !extension(n)).map(String::from).collect())
}

#[test]
fn each_name_that_openssh_knows_is_let_in_when_the_set_has_it_and_refused_else() {
    let Some(dir) = home("algs") else { return };
    let (home, key) = (&dir.0, dir.0.join("id"));
    let mut wrong = Vec::new();
    for (keyword, query, word, set) in lists() {
        for name in openssh_knows(query) {
            let option = format!("{keyword}={name}");
            // A MAC is chosen only beside a cipher that needs one.
            let mut options: Vec<&str> = vec!["-o", option.as_str()];
            if keyword == "MACs" {
                options.extend(["-o", "Ciphers=aes128-ctr"]);
            }
            let (code, err) = finish(openssh_with(home, &key, "accept-new", "", &options, &["true"]));
            let refused = format!("no matching {word} found");
            if set.contains(&name) {
                if code != Some(0) {
                    wrong.push(format!("{option}: in the set, yet {code:?}: {err}"));
                }
            } else if code != Some(255) || !err.contains(&refused) {
                wrong.push(format!("{option}: not in the set, yet {code:?} without {refused:?}: {err}"));
            } else if their_offer(&err).as_ref() != Some(&set) {
                wrong.push(format!("{option}: OpenSSH's `Their offer:` is not the set {set:?}: {err}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{} names wrong:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn a_host_certificate_is_refused_and_the_offer_is_the_host_key() {
    let Some(dir) = home("cert") else { return };
    let options = ["-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com"];
    let (code, err) = finish(openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &options, &["true"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("no matching host key type found"), "{err}");
    assert_eq!(their_offer(&err), Some(vec!["ssh-ed25519".to_string()]), "serve's host key alone: {err}");
}

/// The words of `reply`'s row.
fn words(reply: &str) -> &'static str {
    let row = REPLIES.iter().find(|(r, _, _)| *r == reply).expect("a row of the table");
    row.2.expect("words of OpenSSH's client")
}

#[test]
fn each_refusal_that_openssh_can_cause_sends_its_reply() {
    let Some(dir) = home("replies") else { return };
    let (home, key) = (&dir.0, dir.0.join("id"));
    // USERAUTH_FAILURE: a key of the client that serve does not list.
    keygen(home, &home.join("other"));
    let (code, err) = finish(openssh_with(home, &home.join("other"), "accept-new", "", &[], &["true"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains(words("USERAUTH_FAILURE")), "{err}");
    // CHANNEL_FAILURE: a subsystem that serve does not serve.
    let (code, err) = finish(openssh_with(home, &key, "accept-new", "", &["-s"], &["podssh-no-such-subsystem"]));
    assert_ne!(code, Some(0), "{err}");
    assert!(err.contains(words("CHANNEL_FAILURE")), "{err}");
    // REQUEST_FAILURE: a listener on serve's side, which serve never opens;
    // the session goes on, and OpenSSH warns.
    let options = ["-R", "127.0.0.1:2222:127.0.0.1:1"];
    let (code, err) = finish(openssh_with(home, &key, "accept-new", "", &options, &["sleep 1"]));
    assert_eq!(code, Some(0), "the session goes on: {err}");
    assert!(err.contains(words("REQUEST_FAILURE")), "{err}");
    // Each row without words names where it is pinned, or why none can be.
    for (reply, request, said) in REPLIES {
        assert!(!request.is_empty(), "{reply}");
        if said.is_none() {
            assert!(["CHANNEL_OPEN_FAILURE", "DISCONNECT", "UNIMPLEMENTED"].contains(reply), "{reply}");
        }
    }
}
