//! The Pinggy address in the node's record of pkarr (T-548's step 3, T-445),
//! a module of `tests/pinggy_road.rs` for a build with the iroh road's test
//! servers (feature `iroh-test`): a server of pkarr on the loopback
//! (`podssh_iroh::test_pkarr`, which checks each record's signature with
//! iroh-dns's own reading), a net whose owner names the node `lab` by its
//! key, and `podssh node lab TARGET --pinggy` that puts its tunnel's address
//! there. A member with no `--pinggy-name` and no name kept reaches the node
//! over the Pinggy road with the pair's road down, and `-v` says that the
//! address came from the record. Planted: the client ignores the record's
//! address, and the test fails.

use std::path::{Path, PathBuf};

use podssh_relay::identity::Identity;

use crate::ssh_harness::GREETING;
use crate::{command, run, wait_for, Lab};

/// The byte of the node's key, so that the owner can name it first.
const NODE_SEED: u8 = 0x31;

/// A private key file at `path`, from one byte.
fn key_file(path: &Path, seed: u8) {
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(path, format!("{hex}\n").as_bytes()).unwrap();
}

/// The net `home`, whose owner names the node `lab` by its key, as the
/// client's end took it: the document's path.
fn net_of_the_node(lab: &Lab, dir: &Path) -> PathBuf {
    podssh_relay::cache::private_dir(dir).unwrap();
    let (owner, doc) = (dir.join("owner").to_string_lossy().into_owned(), dir.join("owner.doc"));
    let as_owner = |args: &[&str]| {
        let mut cmd = command(dir, lab.proxy, args);
        let (rc, _, err) = run(cmd.env("PODSSH_NET", &doc));
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    as_owner(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", owner.as_str()]);
    let node = Identity::from_seed(&[NODE_SEED; 32]).public().hex();
    as_owner(&["net", "init", "home", "--owner-key", owner.as_str()]);
    as_owner(&["net", "add", "lab", node.as_str(), "--owner-key", owner.as_str()]);
    let copy = dir.join("serial").to_string_lossy().into_owned();
    std::fs::copy(&doc, &copy).unwrap();
    let client_doc = lab.client_home.join("net.doc");
    let mut cmd = command(&lab.client_home, lab.proxy, &["net", "take", copy.as_str()]);
    let (rc, _, err) = run(cmd.env("PODSSH_NET", &client_doc));
    assert_eq!(rc, 0, "podssh net take: {err}");
    client_doc
}

#[test]
fn a_member_with_no_address_given_or_kept_reaches_the_node_by_the_pinggy_address_of_its_record() {
    let lab = Lab::new("record");
    lab.let_in();
    lab.pair_down();
    let dir = lab.node_home.parent().unwrap().to_path_buf();
    let pkarr = lab.runtime.block_on(podssh_iroh::test_pkarr::spawn(&dir)).expect("a server of pkarr");
    let (url, cert) = (pkarr.url.to_string(), pkarr.cert.to_string_lossy().into_owned());
    // The server is on the loopback, past the stand-in proxy, which passes
    // Pinggy's names alone.
    let env = [("PODSSH_IROH_PKARR", url.as_str()), ("NO_PROXY", "localhost"), ("no_proxy", "localhost")];
    key_file(&lab.node_home.join("node.key"), NODE_SEED);
    let (_node, lines, name, address) = lab.node("node.key", &["--pinggy", "--ca-file", &cert], &env);
    let put = wait_for(&lines, "names the Pinggy tunnel");
    assert!(put.last().unwrap().contains(&format!("names the Pinggy tunnel {name}")), "{put:#?}");
    let key = iroh::PublicKey::from_bytes(&Identity::from_seed(&[NODE_SEED; 32]).public().0).unwrap();
    assert!(pkarr.payload(&key).is_some(), "the server keeps the node's record");

    let client_doc = net_of_the_node(&lab, &dir.join("owner"));
    let kept = lab.client_home.join("cache").join("podssh").join("pinggy-lab.name");
    assert!(!kept.exists(), "no name kept here");
    let mut ssh = lab.ssh(&["-v", "--ca-file", &cert, "node://tester@lab", "greet"]);
    let (rc, out, err) = run(ssh.envs(env).env("PODSSH_NET", &client_doc));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("asking the node's record"), "{err}");
    let order = "the Pinggy road when each road before it failed (the node's record, the last fallback of Q78)";
    assert!(err.contains(order), "{err}");
    let from = format!("the Pinggy road dials {address}, the address of its record of pkarr");
    assert!(err.contains(&from), "the road came from the record: {err}");
    assert!(err.contains("the Pinggy road answered first"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");
    assert!(!kept.exists(), "a record's address is asked again, not kept");
    drop(pkarr);
    drop(lab.runtime);
}
