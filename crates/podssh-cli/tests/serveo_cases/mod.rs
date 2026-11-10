//! The cases of `tests/serveo_road.rs` (T-549), apart from its lab for the
//! length of that file.

use std::process::Stdio;
use std::sync::atomic::Ordering;

use crate::ssh_harness::GREETING;
use crate::{alias_of, command, run, run_with, Lab, SERVER};

/// The node's alias is the first of its key's series, as the test computes
/// it apart from podssh's code; a client that names the node's key with
/// `--node-key`, then one that holds it in its pins, jumps to it with the
/// pair's road down; `PODSSH_LAST_RESORT=no` leaves the pair's road alone.
#[test]
fn the_node_s_alias_is_its_key_s_and_a_client_with_the_key_jumps_to_it_last() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let fingerprint = lab.node_key("node.key");
    let (_node, said, alias) = lab.node("node.key", &["--serveo"], &[]);
    assert_eq!(alias, alias_of(&fingerprint, 0), "the first alias of the node's key: {said:#?}");
    assert_eq!(lab.stand_in.forwards(), vec![(alias.clone(), 22)], "as ssh -R ALIAS:22:localhost:22 asks");
    assert_eq!(lab.stand_in.users(), vec!["anonymous".to_string()], "no local user's name goes to Serveo");
    assert!(said.iter().any(|l| l.contains("nobody vouches for") && l.contains("Q78")), "{said:#?}");
    assert!(said.iter().any(|l| l.contains("raw SSH on port 443")), "443 first: {said:#?}");
    assert!(said.iter().any(|l| l.contains("host key") && l.contains("unpinned")), "{said:#?}");

    let words = ["-v", "--node-key", fingerprint.as_str(), "node://tester@lab", "greet"];
    let (rc, out, err) = run(&mut lab.ssh(&words));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the Serveo road answered first"), "{err}");
    assert!(err.contains("when each road before it failed (the alias of the node's key"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");
    assert!(err.contains(&format!("jumps to {alias}, the first alias")), "{err}");
    assert!(lab.stand_in.jumps.load(Ordering::SeqCst) >= 1, "a client jumped to the alias");

    // The key in the pins of `lab`, as a first session over another road
    // writes it: no flag names it now.
    std::fs::write(lab.cache().join("known-nodes"), format!("lab {fingerprint}\n")).unwrap();
    let (rc, out, err) = run(&mut lab.ssh(&["node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");

    // PODSSH_LAST_RESORT=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_LAST_RESORT", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("Serveo"), "no Serveo road with PODSSH_LAST_RESORT=no: {err}");
    drop(lab.runtime);
}

/// A mebibyte down and a mebibyte up, under the end-to-end channel and the
/// layer, through the stand-in's channels (T-549's Prove).
#[test]
fn a_mebibyte_goes_each_way_under_the_channel() {
    let lab = Lab::new("mebibyte");
    lab.let_in();
    lab.pair_down();
    let fingerprint = lab.node_key("node.key");
    let (_node, _, _) = lab.node("node.key", &["--serveo"], &[]);
    let named = ["--node-key", fingerprint.as_str(), "node://tester@lab"];
    let (rc, out, err) = run(&mut lab.ssh(&[&named[..], &["source 1048576"]].concat()));
    assert_eq!((rc, out.len()), (0, 1 << 20), "{err}");
    let up = lab.client_home.join("up.bin");
    std::fs::write(&up, vec![0x5a; 1 << 20]).unwrap();
    let stdin = Stdio::from(std::fs::File::open(&up).unwrap());
    let (rc, out, err) = run_with(&mut lab.ssh(&[&named[..], &["sink"]].concat()), stdin);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out.split_whitespace().last(), Some("1048576"), "the count of the bytes up: {out:?}");
    drop(lab.runtime);
}

/// The stand-in gives the node's alias to another node's tunnel: the
/// client, which names the first node's key, reaches the stranger and
/// refuses it by the end-to-end channel, with no output of the stranger's.
#[test]
fn a_stranger_at_the_alias_is_refused_by_the_end_to_end_channel() {
    let lab = Lab::new("stranger");
    lab.let_in();
    lab.pair_down();
    let fingerprint = lab.node_key("node.key");
    let (_node, _, alias) = lab.node("node.key", &["--serveo"], &[]);
    let (_stranger, _, other) = lab.node("stranger.key", &["--serveo"], &[]);
    assert_ne!(other, alias, "another key, another alias");
    lab.stand_in.hijack(&alias, &other);
    let jumps = lab.stand_in.jumps.load(Ordering::SeqCst);
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &fingerprint, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "nothing of the stranger's: {out:?}");
    assert!(err.contains("refused the node"), "refused by the end-to-end channel: {err}");
    assert!(lab.stand_in.jumps.load(Ordering::SeqCst) > jumps, "the stranger was reached, and refused");
    drop(lab.runtime);
}

/// Serveo holds the node's first alias, as after an abrupt end of its last
/// tunnel: the node says so and takes the second, where the client, which
/// tries the series in its order, finds it.
#[test]
fn an_alias_that_serveo_holds_sends_the_node_to_the_next_of_its_series() {
    let lab = Lab::new("series");
    lab.let_in();
    lab.pair_down();
    let fingerprint = lab.node_key("node.key");
    lab.stand_in.hold(&alias_of(&fingerprint, 0));
    let (_node, said, alias) = lab.node("node.key", &["--serveo"], &[]);
    assert_eq!(alias, alias_of(&fingerprint, 1), "{said:#?}");
    assert!(said.iter().any(|l| l.contains("refused the alias") && l.contains("the next of its series")), "{said:#?}");
    assert_eq!(lab.stand_in.taken.load(Ordering::SeqCst), 1);
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--node-key", &fingerprint, "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(err.contains(&format!("jumps to {alias}, the second alias")), "{err}");
    drop(lab.runtime);
}

/// A proxy that keeps port 443 shut: the leg takes Serveo's port 22.
#[test]
fn where_the_proxy_refuses_443_the_leg_is_ssh_on_port_22() {
    let lab = Lab::new("port22");
    lab.no_443.store(true, Ordering::SeqCst);
    let (_node, said, _) = lab.node("node.key", &["--serveo"], &[]);
    assert!(said.iter().any(|l| l.contains("raw SSH on port 22")), "{said:#?}");
    drop(lab.runtime);
}

/// A node with no pair and a door serves the road unasked, the last of all:
/// where the Pinggy road is off, and after it reached no server.
#[test]
fn a_node_with_no_other_road_serves_serveo_unasked_after_pinggy_and_names_the_third_party() {
    let lab = Lab::new("unasked");
    for (pinggy, why) in [("no", "PODSSH_PINGGY=no turns the Pinggy road off"), (SERVER, "reached no server")] {
        // A Pinggy server that the proxy refuses to reach: its road fails at once.
        let pinggy = if pinggy == SERVER { "pinggy.refused.test" } else { pinggy };
        let (_node, said, _) = lab.node("node.key", &[], &[("PODSSH_DERP", "no"), ("PODSSH_PINGGY", pinggy)]);
        let unasked = said.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{said:#?}"));
        assert!(unasked.contains(why) && unasked.contains("the last"), "{unasked}");
        assert!(said.iter().any(|l| l.contains("Serveo") && l.contains("PODSSH_LAST_RESORT=no")), "{said:#?}");
    }
    drop(lab.runtime);
}

#[test]
fn the_switches_turn_the_road_off_and_a_node_with_no_door_or_no_server_is_refused_before_it_connects() {
    let lab = Lab::new("refused");
    let allow = lab.allow.to_string_lossy().into_owned();
    let words = ["node", "lab", lab.target.as_str(), "--serveo", "--allow", allow.as_str()];
    for (var, value) in [("PODSSH_LAST_RESORT", "no"), ("PODSSH_SERVEO", "no")] {
        let (rc, out, err) = run(command(&lab.node_home, lab.proxy, &words).env(var, value));
        assert_eq!(rc, 64, "{var}: stdout {out:?}, stderr {err}");
        assert!(err.contains(&format!("{var}=no turns the Serveo road off")), "{err}");
    }
    // With no server named, the catalog's; where it names none, 64.
    if podssh_relay::serveo::Service::hosted().is_none() {
        let (rc, _, err) = run(command(&lab.node_home, lab.proxy, &words).env_remove("PODSSH_SERVEO"));
        assert_eq!(rc, 64, "{err}");
        assert!(err.contains("names no Serveo server"), "{err}");
    }
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--serveo"]));
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("--serveo needs --allow FILE"), "{err}");
    assert!(err.contains("Serveo is a third party that nobody vouches for"), "{err}");
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &[&words[..], &["--pinggy"]].concat()));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--serveo is one road"), "{err}");
    assert!(lab.stand_in.forwards().is_empty(), "no tunnel asked");
    drop(lab.runtime);
}
