//! The OpenTunnel name in the node's record of pkarr (T-611, T-445), a module
//! of `tests/opentunnel_road.rs` for a build with the iroh road's test
//! servers (feature `iroh-test`): a server of pkarr on the loopback
//! (`podssh_iroh::test_pkarr`, which checks each record's signature with
//! iroh-dns's own reading), a net whose owner names the node `lab` by its
//! key, and `podssh node lab TARGET --opentunnel` that puts its name there
//! once its tunnel is ready. A member with no `--opentunnel-name` and no name
//! kept reaches the node over the OpenTunnel road with the pair's road down,
//! and `-v` says that the name came from the record. Planted
//! (`scripts/plants/t611-name-not-read.patch`): the record's parser drops the
//! name, and the test fails.

use std::path::{Path, PathBuf};

use podssh_relay::identity::Identity;

use crate::ssh_harness::GREETING;
use crate::{command, run, wait_for, Lab};

/// The byte of the node's key, so that the owner can name it first.
const NODE_SEED: u8 = 0x32;

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

/// One file of trust for the stand-in's service and the server of pkarr:
/// `--ca-file` takes a bundle, and each end reaches both.
fn bundle(lab: &Lab, cert: &Path, dir: &Path) -> String {
    let mut pem = std::fs::read(&lab.ca).expect("the stand-in's CA");
    pem.extend(std::fs::read(cert).expect("the certificate of the server of pkarr"));
    let both = dir.join("both-ca.pem");
    std::fs::write(&both, pem).unwrap();
    both.to_string_lossy().into_owned()
}

#[test]
fn a_member_with_no_name_given_or_kept_reaches_the_node_by_the_opentunnel_name_of_its_record() {
    let lab = Lab::new("record");
    lab.let_in();
    lab.pair_down();
    let dir = lab.node_home.parent().unwrap().to_path_buf();
    let pkarr = lab.runtime.block_on(podssh_iroh::test_pkarr::spawn(&dir)).expect("a server of pkarr");
    let (url, ca) = (pkarr.url.to_string(), bundle(&lab, &pkarr.cert, &dir));
    // The server is on the loopback, past the stand-in proxy, which passes
    // the service's names alone.
    let env = [("PODSSH_IROH_PKARR", url.as_str()), ("NO_PROXY", "localhost"), ("no_proxy", "localhost")];
    key_file(&lab.node_home.join("node.key"), NODE_SEED);
    let (_node, lines, name, seen) = lab.node_trusting(&ca, &["--opentunnel"], &env);
    let put = format!("names the OpenTunnel name {name}");
    // The record may be put before the bridge attaches, or after.
    if !seen.iter().any(|line| line.contains("names the OpenTunnel name")) {
        let more = wait_for(&lines, "names the OpenTunnel name");
        assert!(more.last().unwrap().contains(&put), "{more:#?}");
    } else {
        assert!(seen.iter().any(|line| line.contains(&put)), "{seen:#?}");
    }
    let key = iroh::PublicKey::from_bytes(&Identity::from_seed(&[NODE_SEED; 32]).public().0).unwrap();
    assert!(pkarr.payload(&key).is_some(), "the server keeps the node's record");

    let client_doc = net_of_the_node(&lab, &dir.join("owner"));
    let kept = lab.client_home.join("cache").join("podssh").join("opentunnel-lab.name");
    assert!(!kept.exists(), "no name kept here");
    let mut ssh = lab.ssh_trusting(&ca, &["-v", "node://tester@lab", "greet"]);
    let (rc, out, err) = run(ssh.envs(env).env("PODSSH_NET", &client_doc));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("asking the node's record"), "{err}");
    assert!(err.contains(&put), "the client read the name of the record: {err}");
    assert!(err.contains("the OpenTunnel road of its record answered first"), "{err}");
    assert!(!kept.exists(), "a record's name is asked again, not kept");
    assert!(lab.stand_in.opens.load(std::sync::atomic::Ordering::SeqCst) >= 1, "a visitor came over the bridge");
    drop(pkarr);
    drop(lab.runtime);
}
