//! The onion road of a pair from end to end (T-578): a node of DERP with a
//! pair serves its onion service in the private Tor network that chutney
//! runs (`scripts/tor-net.sh`; `PODSSH_TEST_TOR_NETWORK` names its
//! arti-client configuration), and `podssh ssh node://` on another home
//! reaches it through the onion road alone, the address given by
//! `PODSSH_ONION`, as a client elsewhere is given it. No other road is on.
//! The test says "did not run" with no private network.

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::derp_croc::store_pair;
use crate::{lines_of, run_within, Lab, Node, GREETING};

/// The service's descriptor on a busy runner's private network.
const PUBLISH: Duration = Duration::from_secs(600);

/// The node's lines until one holds `needle`, within `limit`: that line.
fn line_with(lines: &Receiver<String>, needle: &str, limit: Duration) -> String {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) if line.contains(needle) => return line,
            Ok(line) => seen.push(line),
            Err(_) => panic!("no {needle:?} from the node within {} s: {seen:#?}", limit.as_secs()),
        }
    }
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_its_onion_service() {
    let Some(network) = std::env::var_os("PODSSH_TEST_TOR_NETWORK").filter(|v| !v.is_empty()) else {
        eprintln!("did not run: PODSSH_TEST_TOR_NETWORK names no private Tor network (scripts/tor-net.sh)");
        return;
    };
    let network = network.to_string_lossy().into_owned();
    let lab = Lab::new("onion");
    // The private network: its relays listen on ports from 5000 up.
    let env = [("PODSSH_TOR_NETWORK", network.as_str()), ("PODSSH_TOR_PORTS", "any")];
    lab.let_in();
    store_pair(&lab.node_home);
    store_pair(&lab.client_home);
    let (key, allow, servers) =
        (lab.node_home.join("node.key"), lab.allow.to_string_lossy().into_owned(), lab.servers());
    let key = key.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--allow", &allow, "--key", &key, "--ca-file", &lab.ca, "--derp"];
    let mut cmd = crate::command(&lab.node_home, &words);
    cmd.args(["--derp-server", &servers]).envs(env.iter().copied()).env_remove("PODSSH_ONION");
    let mut child = cmd.stdin(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    let _node = Node(child);
    let said = line_with(&lines, "its address is ", Duration::from_secs(180));
    let address = said
        .split_whitespace()
        .find(|w| w.ends_with(".onion") || w.ends_with(".onion,"))
        .map(|w| w.trim_end_matches(','))
        .unwrap_or_else(|| panic!("no address in {said:?}"))
        .to_string();
    let began = Instant::now();
    line_with(&lines, "its descriptor is published", PUBLISH);
    eprintln!("the node's descriptor was published in {} s", began.elapsed().as_secs());

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.envs(env.iter().copied()).env("PODSSH_ONION", &address).env("PODSSH_DERP", "no");
    let began = Instant::now();
    let (rc, out, err) = run_within(&mut client, Duration::from_secs(240));
    let node_said: Vec<String> = lines.try_iter().collect();
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}; the node said: {node_said:#?}");
    assert_eq!(out, GREETING, "the command's output over the onion road");
    assert!(err.contains("onion road answered first"), "{err}");
    assert!(err.contains("carries this session"), "the line of the third party: {err}");
    eprintln!("podssh ssh node:// through the onion road in {:.1} s", began.elapsed().as_secs_f64());
    drop(lab.runtime);
}
