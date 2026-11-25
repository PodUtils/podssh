//! A gateway of the net (T-902) on documents signed here, in a file that
//! stands for the one this host holds: its routes at the start; a document
//! whose signature fails, which leaves the routes in force with one line,
//! said once; a newer serial, swapped in; a section removed, which lets
//! nobody in; and a document past its end, which closes the gateway.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::PrivateKey;
use serde_json::{json, Value};

use super::*;
use crate::keygen_sign::Signing;
use crate::net::doc::Doc;
use crate::net::sign;

/// A scratch directory, removed when the test ends, also on a failure.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let dir = std::env::temp_dir().join(format!("podssh-gateway-net-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn line_of(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

/// One route block for `pattern`, signed by the CA of `ca`.
fn block(pattern: &str, ca: &str, host: &str, user: &str) -> String {
    format!("route {pattern}\n  upstream 10.0.0.5:22\n  host-key {host}\n  principal {pattern}\n  ca-key {ca}\n  key {user}\n")
}

/// The clocks of the test: within the documents' life, and past its end.
fn within() -> i64 {
    1_800_000_000
}

fn past_the_end() -> i64 {
    4_200_000_000
}

/// The owner's documents, each the one before with a change, signed.
struct Owner {
    signing: Signing,
    doc: Doc,
}

impl Owner {
    fn new() -> Owner {
        let key = generate(KeyKind::Ed25519, "").unwrap();
        let doc = Doc::new("home", line_of(&key).trim(), 1_793_577_600, 4_102_444_800).unwrap();
        Owner { signing: Signing::Key(Box::new(key)), doc }
    }

    /// The next serial with `gateways` as given, signed: its bytes.
    fn next(&mut self, gateways: Option<Value>) -> Vec<u8> {
        let next = self.doc.next_whole(1_793_577_700 + self.doc.serial as i64, 4_102_444_800, |whole| {
            match gateways {
                Some(value) => whole.insert(crate::net::gateway::FIELD.into(), value),
                None => whole.remove(crate::net::gateway::FIELD),
            };
        });
        self.doc = next.unwrap();
        sign::sign_with(&self.doc, &self.signing).unwrap().to_bytes()
    }
}

/// `bytes` in place of the document held, as `store` keeps one: writable
/// by this user alone.
fn hold(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn a_gateway_of_the_net_keeps_its_routes_through_a_bad_signature_and_takes_each_newer_serial() {
    let s = scratch();
    let held = s.0.join("net.doc");
    let (ca, host, user) = (
        generate(KeyKind::Ed25519, "").unwrap(),
        line_of(&generate(KeyKind::Ed25519, "").unwrap()),
        line_of(&generate(KeyKind::Ed25519, "").unwrap()),
    );
    let ca_line = line_of(&ca);
    let cas = vec![(s.0.join("gateway_ca"), Arc::new(ca))];
    let mut owner = Owner::new();
    let section = |text: String| Some(json!({ "gw": { "routes": text } }));

    // Serial 2: alice's route, taken at the start.
    hold(&held, &owner.next(section(block("alice", &ca_line, &host, &user))));
    let net = Arc::new(NetRoutes::new("gw", Place::File(held.clone()), cas, within));
    let (table, notes) = Table::from_source(Box::new(net.clone())).expect("the document reads");
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!((table.now().len(), net.serial(), table.shown()), (1, Some(2), "net:gw".to_string()));
    assert!(table.now().route("alice").is_some() && table.closed().is_none());
    let mut said = None;
    assert!(net.look(&table, &mut said).is_empty(), "the serial in force says nothing");

    // Serial 3's bytes under serial 2's signature: the routes stay, said once.
    let good_two = std::fs::read(&held).unwrap();
    let three = owner.next(section(block("bob", &ca_line, &host, &user)));
    let (body, _) = sign::split(&three).unwrap();
    let (_, signature) = sign::split(&good_two).unwrap();
    hold(&held, &[body, signature].concat());
    let lines = net.look(&table, &mut said);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("cannot be trusted") && lines[0].contains("the routes of serial 2 stay, 1 in all"),
        "{}",
        lines[0]
    );
    assert!(net.look(&table, &mut said).is_empty(), "the same fault is said once");
    assert!(table.now().route("alice").is_some() && table.now().route("bob").is_none());
    assert_eq!(table.reload().map(|(n, _)| n).ok(), None, "SIGHUP keeps them too");

    // Serial 3 itself: swapped in.
    hold(&held, &three);
    let lines = net.look(&table, &mut said);
    assert_eq!(lines, ["net:gw: the routes of serial 3 taken, 1 in all"]);
    assert!(table.now().route("bob").is_some() && table.now().route("alice").is_none());

    // A route whose CA this host does not hold is left out, with its line.
    let other = line_of(&generate(KeyKind::Ed25519, "").unwrap());
    hold(&held, &owner.next(section(block("bob", &ca_line, &host, &user) + &block("carol", &other, &host, &user))));
    let lines = net.look(&table, &mut said);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("route carol (line 7) refused") && lines[1].ends_with("serial 4 taken, 1 in all"));

    // The owner removes the section: nobody passes, never the routes before.
    hold(&held, &owner.next(None));
    let lines = net.look(&table, &mut said);
    assert!(lines.iter().any(|l| l.contains("holds no routes for the gateway gw")), "{lines:?}");
    assert!(table.now().is_empty(), "a removal is the owner's word");

    // A document past its end closes the gateway, whatever its routes.
    hold(&held, &owner.next(section(block("alice", &ca_line, &host, &user))));
    let late = NetRoutes::new("gw", Place::File(held.clone()), Vec::new(), past_the_end);
    late.read().unwrap();
    let why = late.closed().expect("closed past the end");
    assert!(why.contains("serial 6") && why.contains("podssh net renew"), "{why}");
}

#[test]
fn a_gateway_of_the_net_with_no_document_or_a_broken_one_does_not_read() {
    let s = scratch();
    let held = s.0.join("net.doc");
    let net = NetRoutes::new("gw", Place::File(held.clone()), Vec::new(), within);
    let why = net.read().err().expect("no document");
    assert!(why.contains("holds no net's document"), "{why}");
    hold(&held, b"{\"podssh-net\": 1}\n");
    let why = net.read().err().expect("no signature");
    assert!(why.contains("cannot be trusted") && !why.contains('\n'), "{why}");
}
