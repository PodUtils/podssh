//! croc's relay road beside a `--derp` node's own pair (T-694): the node
//! holds a pair whose relay is down, and serves the DERP road with croc's
//! relay road beside it, in the pair's rooms; a client of the same pair
//! with its DERP road off and the pair's road down reaches the node through
//! croc's road alone. The relay and croc-web's bridge are the stand-ins of
//! podssh-relay's tests (`croc_stand_in`, from croc's source), on the
//! loopback, named by `PODSSH_CROC`.

use std::process::Stdio;
use std::time::Duration;

use crate::croc_stand_in::{Bridge, Relay};
use crate::{lines_of, run, wait_for, Lab, Node, GREETING};

/// A pair under `lab` in the cache of `home`, whose relay is a port of the
/// loopback where nothing listens: its road fails at once at both ends.
fn store_pair(home: &std::path::Path) {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: closed };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    // The repository's fixture form of a token, which names no credential.
    let token = |kind: &str| format!("testonly{kind}{}", "0".repeat(56 - kind.len()));
    let body = serde_json::json!({
        "name": "p-0123456789abcdef0123456789abcdef",
        "node_token": token("node"),
        "connect_token": token("connect"),
        "stop_token": token("stop"),
        "expires": now + 72 * 3600 * 1000,
    });
    let pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), now).expect("a test pair");
    podssh_relay::pair::store_in_first(&[home.join("cache").join("podssh")], "lab", &pair).expect("stored");
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_croc_s_relay_road() {
    let lab = Lab::new("croc");
    lab.let_in();
    let (relay, bridge) = lab.runtime.block_on(async {
        let relay = Relay::start(podssh_relay::croc::relay::PASSWORD, Duration::from_millis(100)).await;
        let bridge = Bridge::start(vec![relay.addr; 4]).await;
        (relay, bridge)
    });
    let url = format!("ws://127.0.0.1:{}{}", bridge.url.port, bridge.url.target);
    store_pair(&lab.node_home);
    store_pair(&lab.client_home);
    let (key, allow, servers) =
        (lab.node_home.join("node.key"), lab.allow.to_string_lossy().into_owned(), lab.servers());
    let key = key.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--allow", &allow, "--key", &key, "--ca-file", &lab.ca, "--derp"];
    let mut cmd = crate::command(&lab.node_home, &words);
    cmd.args(["--derp-server", &servers]).env("PODSSH_CROC", &url);
    let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    let _node = Node(child);
    let started = wait_for(&lines, "ticket derp:");
    // The node waits in the pair's first room once its road is up.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while relay.rooms() == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(relay.rooms() > 0, "the node waits in a room of croc's relay: {started:#?}");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.env("PODSSH_CROC", &url).env("PODSSH_DERP", "no");
    let (rc, out, err) = run(&mut client);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over croc's road");
    assert!(err.contains("croc's relay road answered first"), "{err}");
    drop(bridge);
    drop(lab.runtime);
}
