//! Yggdrasil's road beside a `--derp` node's own pair (T-735), with the
//! feature `yggdrasil`: the node holds a pair whose relay is down, and serves
//! the DERP road with Yggdrasil's road beside it, linked to a node of
//! yggdrasil-go's own (`PODSSH_YGGDRASIL` names its `ws://` peer) under the
//! key that the pair's secret makes; a client of the same pair, with its DERP
//! road off and the pair's road down, reaches the node through Yggdrasil's
//! road alone. yggdrasil-go is `PODSSH_YGG_TEST_BIN`, or `yggdrasil` on the
//! PATH; the check says that it did not run where there is none. With
//! `PODSSH_YGG_TEST_PEER=URL`, the two ends link to that peer in its place:
//! the short live run through a public peer (ygg-interop.yml).

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::derp_croc::store_pair;
use crate::{lines_of, run_within, wait_for, Lab, Node, GREETING};

/// yggdrasil-go's node, ended when this drops.
struct Peer {
    child: Child,
    dir: std::path::PathBuf,
    url: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(dir: std::path::PathBuf) -> Option<Peer> {
    let bin = std::env::var("PODSSH_YGG_TEST_BIN").unwrap_or_else(|_| "yggdrasil".into());
    let made = Command::new(&bin).args(["-genconf", "-json"]).stderr(Stdio::null()).output().ok()?;
    let mut conf: serde_json::Value = serde_json::from_slice(&made.stdout).ok()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).ok()?.port();
    conf["Listen"] = serde_json::json!([format!("ws://127.0.0.1:{port}")]);
    conf["MulticastInterfaces"] = serde_json::json!([]);
    conf["IfName"] = serde_json::json!("none");
    conf["AdminListen"] = serde_json::json!("none");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join("node.json");
    std::fs::write(&path, serde_json::to_vec(&conf).ok()?).ok()?;
    let child = Command::new(&bin)
        .arg("-useconffile")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let peer = Peer { child, dir, url: format!("ws://127.0.0.1:{port}/") };
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "yggdrasil did not listen on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(peer)
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_yggdrasil_s_road() {
    let lab = Lab::new("ygg");
    let (named, peer) = match std::env::var("PODSSH_YGG_TEST_PEER") {
        Ok(named) => (named, None),
        Err(_) => {
            let Some(peer) = start(lab.node_home.join("ygg")) else {
                eprintln!("did not run: no yggdrasil here (PODSSH_YGG_TEST_BIN, or yggdrasil on the PATH)");
                return;
            };
            (peer.url.clone(), Some(peer))
        }
    };
    let env = [("PODSSH_YGGDRASIL", named.as_str())];
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
    wait_for(&lines, "waits for its operators in Yggdrasil's network");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.envs(env.iter().copied()).env("PODSSH_DERP", "no");
    let began = Instant::now();
    let (rc, out, err) = run_within(&mut client, Duration::from_secs(90));
    let node_said: Vec<String> = lines.try_iter().collect();
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}; the node said: {node_said:#?}");
    assert_eq!(out, GREETING, "the command's output over Yggdrasil's road");
    assert!(err.contains("Yggdrasil's road answered first"), "{err}");
    eprintln!("podssh ssh node:// through Yggdrasil's road in {:.1} s", began.elapsed().as_secs_f64());
    drop(peer);
    drop(lab.runtime);
}
