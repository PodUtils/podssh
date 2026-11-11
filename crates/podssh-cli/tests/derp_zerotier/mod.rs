//! ZeroTier's road beside a `--derp` node's own pair (T-733), with the
//! feature `zerotier-test`: the node holds a pair whose relay is down, and
//! serves the DERP road with ZeroTier's beside it, as a member of the pair's
//! own network at the identity that both ends make of the pair's secret; a
//! client of the same pair, with its DERP road off and the pair's road down,
//! reaches the node through ZeroTier's road alone. The relay and the root
//! are podssh-zerotier's stand-in on the loopback, named by
//! `PODSSH_ZEROTIER`, with its planet in `PODSSH_ZEROTIER_PLANET`. A client
//! of another pair finds no node there.

use std::process::Stdio;

use crate::derp_croc::store_pair;
use crate::{lines_of, run, wait_for, Lab, Node, GREETING};

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_zerotier_s_road() {
    let lab = Lab::new("zerotier");
    lab.let_in();
    let stand_in = lab.runtime.block_on(podssh_cli::zerotier_stand_in::start()).expect("the stand-in");
    let planet = lab.node_home.join("planet");
    std::fs::write(&planet, &stand_in.planet).unwrap();
    let (relay, planet) = (stand_in.relay.to_string(), planet.to_string_lossy().into_owned());
    store_pair(&lab.node_home);
    store_pair(&lab.client_home);
    let (key, allow, servers) =
        (lab.node_home.join("node.key"), lab.allow.to_string_lossy().into_owned(), lab.servers());
    let key = key.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--allow", &allow, "--key", &key, "--ca-file", &lab.ca, "--derp"];
    let mut cmd = crate::command(&lab.node_home, &words);
    cmd.args(["--derp-server", &servers]).env("PODSSH_ZEROTIER", &relay).env("PODSSH_ZEROTIER_PLANET", &planet);
    let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    let _node = Node(child);
    wait_for(&lines, "ticket derp:");
    let waits = wait_for(&lines, "the node waits at");
    assert!(waits.iter().any(|l| l.contains("on the network ff")), "{waits:#?}");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.env("PODSSH_ZEROTIER", &relay).env("PODSSH_ZEROTIER_PLANET", &planet).env("PODSSH_DERP", "no");
    let (rc, out, err) = run(&mut client);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over ZeroTier's road");
    assert!(err.contains("ZeroTier's road answered first"), "{err}");
    drop(stand_in);
    drop(lab.runtime);
}
