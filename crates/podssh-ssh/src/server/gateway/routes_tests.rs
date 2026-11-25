//! The route table (T-836): each form of a file against one rule, in one
//! table: what reads, and the line and the words of what does not.

use std::path::{Path, PathBuf};

use russh::keys::PrivateKey;

use super::*;
use crate::keygen::{generate, KeyKind};

/// A fresh public key's line, `ssh-ed25519 BASE64`.
fn line_of(key: &PrivateKey) -> String {
    key.public_key().to_openssh().expect("a public key's line")
}

/// The keys of the table's files: `HOST` is the upstream's, `ALICE` and
/// `BOB` are users'.
struct Keys {
    host: String,
    alice: String,
    bob: String,
}

fn keys() -> Keys {
    let make = || line_of(&generate(KeyKind::Ed25519, "").expect("a key"));
    Keys { host: make(), alice: make(), bob: make() }
}

/// `text` with the keys put in, read with a CA that each path gives.
fn parse(text: &str, k: &Keys) -> Result<Routes, String> {
    let text = text.replace("HOST", &k.host).replace("ALICE", &k.alice).replace("BOB", &k.bob);
    let mut asked: Vec<PathBuf> = Vec::new();
    let mut ca = |path: &Path| {
        asked.push(path.to_path_buf());
        if path.ends_with("missing") {
            return Err(format!("{}: no such file", path.display()));
        }
        generate(KeyKind::Ed25519, "").map_err(|e| e.to_string())
    };
    let routes = Routes::parse(&text, Path::new("/etc/podssh"), &mut ca);
    // A CA file read once, however many routes name it.
    let mut unique = asked.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), asked.len(), "a CA file read twice: {asked:?}");
    routes
}

const WHOLE: &str = "\
# a comment
route alice
    upstream 10.0.0.5:2222
    host-key HOST
    principal alice
    ca-key ca
    key ALICE

route team-*
\tupstream [fd00::5]
\thost-key HOST
\tprincipal deploy
\tca-key /etc/podssh/ca
\tkey ALICE
\tkey BOB
\tsource-address 10.0.0.1,10.1.0.0/16
";

/// Each file of the table: Ok with how many routes, or Err with words of
/// the one line that says why.
#[test]
fn each_file_reads_or_says_its_line_and_why() {
    let k = keys();
    let base = "route a\nupstream h:22\nhost-key HOST\nprincipal p\nca-key ca\nkey ALICE\n";
    let without = |part: &str| base.lines().filter(|l| !l.starts_with(part)).collect::<Vec<_>>().join("\n");
    let with = |more: &str| format!("{base}{more}\n");
    let cases: Vec<(&str, String, Result<usize, &str>)> = vec![
        ("the whole example", WHOLE.into(), Ok(2)),
        ("one route", base.into(), Ok(1)),
        ("no route at all", "# nothing\n\n".into(), Ok(0)),
        ("a part before any route", format!("upstream h:22\n{base}"), Err("line 1: upstream before any route")),
        ("no upstream", without("upstream"), Err("route a has no upstream")),
        ("no host key", without("host-key"), Err("route a has no host-key")),
        ("no principal", without("principal"), Err("route a has no principal")),
        ("no CA", without("ca-key"), Err("route a has no ca-key")),
        ("no key", without("key ALICE"), Err("route a has no key")),
        ("a part twice", with("upstream h:23"), Err("line 7: upstream twice")),
        ("an unknown word", with("password x"), Err("line 7: password is not a part of a route")),
        ("a part with no value", with("principal"), Err("line 7: principal with no value")),
        ("a route with no pattern", "route\n".into(), Err("line 1: route with no pattern")),
        ("a pattern of two words", "route a b\n".into(), Err("one word of printable ASCII")),
        ("the same pattern twice", format!("{base}{base}"), Err("line 7: route a twice")),
        ("port zero", base.replace("h:22", "h:0"), Err("\"0\" is not a TCP port")),
        ("a port past 65535", base.replace("h:22", "h:65536"), Err("is not a TCP port")),
        ("IPv6 with no brackets", base.replace("h:22", "fd00::5:22"), Err("give HOST:PORT")),
        ("no host", base.replace("h:22", ":22"), Err("give HOST:PORT")),
        ("a host key that does not read", base.replace("HOST", "ssh-ed25519 AAAA"), Err("line 3: not a public key")),
        ("a user key that does not read", base.replace("key ALICE", "key nonsense"), Err("line 6: not a public key")),
        ("a principal list", base.replace("principal p", "principal a,b"), Err("with no comma")),
        ("a principal as an option", base.replace("principal p", "principal -o"), Err("with no comma")),
        ("a source address that does not read", with("source-address nowhere"), Err("Invalid source-address")),
        ("a CA that does not read", base.replace("ca-key ca", "ca-key missing"), Err("line 1: ca-key /etc/podssh/")),
        ("a control character", with("key \u{1b}[2J"), Err("line 7: a control character")),
    ];
    for (what, text, expected) in cases {
        match (parse(&text, &k), expected) {
            (Ok(routes), Ok(n)) => assert_eq!(routes.len(), n, "{what}"),
            (Err(said), Err(words)) => assert!(said.contains(words), "{what}: {said:?} lacks {words:?}"),
            (got, wanted) => panic!("{what}: {:?}, not {wanted:?}", got.map(|r| r.len())),
        }
    }
}

/// The first route that matches decides, by name; its keys alone may take
/// it; a name that no route matches has none.
#[test]
fn the_first_match_decides_and_lists_its_own_keys() {
    let k = keys();
    let routes = parse(WHOLE, &k).expect("the example reads");
    let alice = routes.route("alice").expect("alice's route");
    assert_eq!((alice.host.as_str(), alice.port, alice.principal.as_str()), ("10.0.0.5", 2222, "alice"));
    assert_eq!(alice.ca_path, Path::new("/etc/podssh/ca"), "a relative CA beside the file");
    let bob = PublicKey::from_openssh(&k.bob).unwrap();
    let alice_key = PublicKey::from_openssh(&k.alice).unwrap();
    assert!(alice.admits(&alice_key) && !alice.admits(&bob), "bob's key is not alice's route's");
    let team = routes.route("team-web").expect("a team route");
    assert_eq!((team.host.as_str(), team.port), ("fd00::5", 22), "no port is 22");
    assert!(team.admits(&bob) && team.admits(&alice_key));
    assert_eq!(team.source_address.as_deref(), Some("10.0.0.1,10.1.0.0/16"));
    assert!(Arc::ptr_eq(&alice.ca, &team.ca), "one CA file is one key");
    for unmatched in ["", "bob", "Alice", "team", "alice2"] {
        assert!(routes.route(unmatched).is_none(), "{unmatched:?} has a route");
    }
}

/// The reader of a net's document (T-902): `plan` keeps each `ca-key` word
/// whole, a public key with its comment as a file, reads no CA, and gives
/// the same refusals as a file; `with_ca` and `Routes::of` make the routes.
#[test]
fn plan_keeps_the_ca_word_whole_and_reads_no_ca() {
    let k = keys();
    let ca = generate(KeyKind::Ed25519, "").expect("a CA");
    let public = format!("{} the gateway's CA", line_of(&ca));
    let text =
        format!("route alice\nupstream h\nhost-key {}\nprincipal alice\nca-key {public}\nkey {}\n", k.host, k.alice);
    let planned = plan(&text).expect("the blocks read");
    assert_eq!(planned.len(), 1);
    assert_eq!((planned[0].pattern.as_str(), planned[0].line, planned[0].ca.as_str()), ("alice", 1, public.as_str()));
    let route = planned[0].clone().with_ca(PathBuf::from("/etc/podssh/gateway_ca"), Arc::new(ca));
    let routes = Routes::of(vec![route]);
    assert_eq!(routes.route("alice").map(|r| (r.host.clone(), r.port)), Some(("h".to_string(), 22)));
    let why = plan(&text.replace("principal alice\n", "")).err().expect("no principal");
    assert!(why.contains("line 1: route alice has no principal"), "{why}");
}
