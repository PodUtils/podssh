//! A gateway's section of the net's document (T-902): each form of it
//! against one rule, in one table: what the gateway takes, which route it
//! leaves out with a line, and the words of a section that it refuses; and
//! the owner's strict check before a signature, in a second table.

use std::path::PathBuf;
use std::sync::Arc;

use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::PrivateKey;
use serde_json::{json, Value};

use super::*;

const OWNER: &str = include_str!("testdata/owner.pub");

/// A fresh key, and its public line.
fn key() -> (PrivateKey, String) {
    let key = generate(KeyKind::Ed25519, "").expect("a key");
    let line = key.public_key().to_openssh().expect("a public line");
    (key, line)
}

/// A document of the net home, serial 2, with `gateways` as given.
fn doc_with(gateways: Option<Value>) -> Doc {
    let first = Doc::new("home", OWNER.trim(), 1_793_577_600, 4_102_444_800).unwrap();
    let next = first.next_whole(1_793_577_700, 4_102_444_800, |whole| {
        if let Some(gateways) = gateways {
            whole.insert(FIELD.into(), gateways);
        }
    });
    next.unwrap()
}

/// One route block for `pattern`, its CA the word `ca`.
fn block(pattern: &str, ca: &str, host: &str, user: &str) -> String {
    format!("route {pattern}\n  upstream 10.0.0.5:22\n  host-key {host}\n  principal {pattern}\n  ca-key {ca}\n  key {user}\n")
}

/// A case of the section's table: its words, the section, and what it gives.
type Case<'a> = (&'a str, Option<Value>, Result<(usize, usize), &'a str>);

/// The section of the gateway `gw` in each form: Ok with the count of the
/// routes taken and of the lines of a route left out, or Err with words of
/// the one line that refuses the section.
#[test]
fn each_section_is_taken_or_leaves_out_a_route_or_is_refused_with_one_line() {
    let ((ca_a, ca_a_line), (_, ca_b_line), (_, host), (_, user)) = (key(), key(), key(), key());
    let cas: Vec<Ca> = vec![(PathBuf::from("/etc/podssh/gateway_ca"), Arc::new(ca_a))];
    let good = block("alice", &ca_a_line, &host, &user);
    let routes = |text: String| Some(json!({ "gw": { "routes": text } }));
    let cases: Vec<Case> = vec![
        ("one route of a CA held", routes(good.clone()), Ok((1, 0))),
        ("a CA that this host does not hold", routes(block("bob", &ca_b_line, &host, &user)), Ok((0, 1))),
        ("a ca-key that is a file", routes(block("bob", "/etc/podssh/ca", &host, &user)), Ok((0, 1))),
        ("one route of each", routes(good.clone() + &block("bob", &ca_b_line, &host, &user)), Ok((1, 1))),
        ("no section at all", None, Err("holds no routes for the gateway gw")),
        (
            "another gateway's alone",
            Some(json!({ "other": { "routes": good.clone() } })),
            Err("holds no routes for the gateway"),
        ),
        ("gateways that are no object", Some(json!(["gw"])), Err("\"gateways\" is not an object")),
        ("a gateway that is no object", Some(json!({ "gw": "route alice" })), Err("the gateway gw of the document")),
        ("a later podssh's field", Some(json!({ "gw": { "routes": "", "deny": [] } })), Err("\"deny\"")),
        ("no routes", Some(json!({ "gw": {} })), Err("has no \"routes\"")),
        ("routes that are no text", Some(json!({ "gw": { "routes": 1 } })), Err("is not text")),
        ("a block with no host key", routes(good.replace(&format!("host-key {host}"), "")), Err("has no host-key")),
        ("an unknown word", routes(format!("{good}  password x\n")), Err("line 7: password")),
    ];
    for (what, gateways, expected) in cases {
        let doc = doc_with(gateways);
        match (routes_of(&doc, "gw", &cas), expected) {
            (Ok((routes, notes)), Ok((n, left))) => {
                assert_eq!((routes.len(), notes.len()), (n, left), "{what}: {notes:?}");
                for note in &notes {
                    assert!(note.contains("refused") && !note.contains('\n'), "{what}: {note}");
                }
            }
            (Err(said), Err(words)) => {
                assert!(said.contains(words), "{what}: {said:?} lacks {words:?}");
                assert!(said.contains("the net home (serial 2)") && !said.contains('\n'), "{what}: {said}");
            }
            (got, wanted) => panic!("{what}: {:?}, not {wanted:?}", got.map(|(r, n)| (r.len(), n))),
        }
    }
}

/// A route taken signs with the key of `--gateway-ca` whose public half
/// the document names, and keeps its CA file for the log; the line of a
/// route left out names the fingerprint and the keys held.
#[test]
fn a_route_takes_the_ca_whose_public_half_the_document_names() {
    let ((ca_a, ca_a_line), (ca_b, ca_b_line), (_, host), (_, user)) = (key(), key(), key(), key());
    let print_b = fingerprint(ca_b.public_key());
    let a = (PathBuf::from("/etc/podssh/a"), Arc::new(ca_a));
    let text = block("alice", &ca_a_line, &host, &user) + &block("bob", &ca_b_line, &host, &user);
    let doc = doc_with(Some(json!({ "gw": { "routes": text } })));
    let (routes, notes) = routes_of(&doc, "gw", std::slice::from_ref(&a)).unwrap();
    let alice = routes.route("alice").expect("alice's route");
    assert!(Arc::ptr_eq(&alice.ca, &a.1) && alice.ca_path == a.0);
    assert!(routes.route("bob").is_none(), "a route of a CA not held");
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("route bob (line 7)") && notes[0].contains(&print_b), "{}", notes[0]);
    assert!(notes[0].contains(&fingerprint(a.1.public_key())), "the keys held: {}", notes[0]);
    let (none, said) = routes_of(&doc, "gw", &[]).unwrap();
    assert!(none.is_empty() && said.iter().all(|n| n.contains("none given")), "{said:?}");
}

/// The owner's check before a signature: the blocks as the route file's
/// reader reads them, each `ca-key` a public key, one route at least, and a
/// name that a net takes.
#[test]
fn the_owner_signs_no_section_that_a_gateway_would_refuse() {
    let ((_, ca), (_, host), (_, user)) = (key(), key(), key());
    let good = block("alice", &ca, &host, &user);
    let cases: Vec<(&str, &str, String, Result<usize, &str>)> = vec![
        ("one route", "gw", good.clone(), Ok(1)),
        ("two routes", "gw", good.clone() + &block("bob", &ca, &host, &user), Ok(2)),
        ("a CA file in place of its public key", "gw", block("a", "ca", &host, &user), Err("line 1: ca-key in a net")),
        ("a private key's path", "gw", block("a", "/etc/ca", &host, &user), Err("stays on the gateway's host")),
        ("no route", "gw", "# none\n".into(), Err("no route, so nobody could pass the gateway gw")),
        ("no key", "gw", good.replace(&format!("key {user}"), ""), Err("route alice has no key")),
        ("a name with a dot", "gw.lab", good.clone(), Err("the gateway's name")),
        ("a control character", "gw", format!("{good}\u{1b}[2J\n"), Err("a control character")),
    ];
    for (what, name, text, expected) in cases {
        match (check(name, &text), expected) {
            (Ok(n), Ok(want)) => assert_eq!(n, want, "{what}"),
            (Err(said), Err(words)) => assert!(said.contains(words), "{what}: {said:?} lacks {words:?}"),
            (got, wanted) => panic!("{what}: {got:?}, not {wanted:?}"),
        }
    }
}
