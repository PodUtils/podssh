//! HyperDHT's road beside a `--derp` node's own pair (T-736), with the
//! feature `hyperdht`: the node holds a pair whose relay is down, and serves
//! the DERP road with HyperDHT's road beside it, in a private DHT of Node.js's
//! own `hyperdht` (`PODSSH_HYPERDHT` names its bootstrap) under the key that
//! the pair's secret makes; a client of the same pair, with its DERP road off
//! and the pair's road down, reaches the node through HyperDHT's road alone.
//! The package's directory is `PODSSH_HYPERDHT_TEST_NODE_PATH`; the check
//! says that it did not run where there is none, or no `node`. With
//! `PODSSH_HYPERDHT_TEST_BOOTSTRAP=HOST:PORT[,...]`, the two ends join that
//! DHT in its place: the short live run through the public one.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::derp_croc::store_pair;
use crate::{lines_of, run_within, wait_for, Lab, Node, GREETING};

/// The private DHT, ended when this drops (its stdin closes).
struct Testnet {
    child: Child,
    bootstrap: String,
}

impl Drop for Testnet {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn testnet() -> Option<Testnet> {
    let modules = std::env::var("PODSSH_HYPERDHT_TEST_NODE_PATH").ok()?;
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../podssh-relay/tests/hyperdht/testnet.js");
    let mut child = Command::new("node")
        .arg(script)
        .env("NODE_PATH", modules)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    let out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut bootstrap = Vec::new();
    loop {
        let line = rx.recv_timeout(Duration::from_secs(30)).expect("the testnet said ready");
        if let Some(at) = line.strip_prefix("bootstrap ") {
            bootstrap.push(at.to_string());
        } else if line == "ready" {
            break;
        }
    }
    Some(Testnet { child, bootstrap: bootstrap.join(",") })
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_hyperdht_s_road() {
    let lab = Lab::new("dht");
    let (named, net) = match std::env::var("PODSSH_HYPERDHT_TEST_BOOTSTRAP") {
        Ok(named) => (named, None),
        Err(_) => {
            let Some(net) = testnet() else {
                eprintln!("did not run: no hyperdht package here (PODSSH_HYPERDHT_TEST_NODE_PATH) or no node");
                return;
            };
            (net.bootstrap.clone(), Some(net))
        }
    };
    let env = [("PODSSH_HYPERDHT", named.as_str())];
    lab.let_in();
    store_pair(&lab.node_home);
    store_pair(&lab.client_home);
    let (key, allow, servers) =
        (lab.node_home.join("node.key"), lab.allow.to_string_lossy().into_owned(), lab.servers());
    let key = key.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--allow", &allow, "--key", &key, "--ca-file", &lab.ca, "--derp"];
    let mut cmd = crate::command(&lab.node_home, &words);
    cmd.args(["--derp-server", &servers]).envs(env.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    let _node = Node(child);
    wait_for(&lines, "ticket derp:");
    wait_for(&lines, "waits for its operators in HyperDHT");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.envs(env.iter().copied()).env("PODSSH_DERP", "no");
    let began = Instant::now();
    let (rc, out, err) = run_within(&mut client, Duration::from_secs(90));
    let node_said: Vec<String> = lines.try_iter().collect();
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}; the node said: {node_said:#?}");
    assert_eq!(out, GREETING, "the command's output over HyperDHT's road");
    assert!(err.contains("HyperDHT's road answered first"), "{err}");
    eprintln!("podssh ssh node:// through HyperDHT's road in {:.1} s", began.elapsed().as_secs_f64());
    drop(net);
    drop(lab.runtime);
}
