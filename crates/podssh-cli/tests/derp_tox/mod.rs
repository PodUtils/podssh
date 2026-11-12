//! The Tox road beside a `--derp` node's own pair (T-734), with the feature
//! `tox`: the node holds a pair whose relay is down, and serves the DERP
//! road with the Tox road beside it, waiting on a relay of c-toxcore's own
//! (`tox-bootstrapd` on the loopback, named by `PODSSH_TOX`) under the key
//! that the pair's secret makes; a client of the same pair, with its DERP
//! road off and the pair's road down, reaches the node through the Tox road
//! alone. The check says that it did not run when this host has no
//! `tox-bootstrapd` (`apt install toxcore-utils`). With
//! `PODSSH_TOX_TEST_RELAY=IP:PORT=KEY`, the two ends meet on that relay in
//! its place: the short live run through a public node (tox-interop.yml).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::derp_croc::store_pair;
use crate::{lines_of, run_within, wait_for, Lab, Node, GREETING};

/// c-toxcore's relay, ended when this drops: its port and its key in hex.
struct Relay {
    child: Child,
    dir: std::path::PathBuf,
    port: u16,
    key: String,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).expect("a free port")
}

fn start(dir: std::path::PathBuf) -> Option<Relay> {
    std::fs::create_dir_all(&dir).ok()?;
    let (udp, tcp) = (free_port(), free_port());
    let conf = dir.join("conf");
    let text = format!(
        "port = {udp}\nkeys_file_path = \"{}\"\npid_file_path = \"{}\"\nenable_ipv6 = false\n\
         enable_ipv4_fallback = true\nenable_lan_discovery = false\nenable_tcp_relay = true\n\
         tcp_relay_ports = [{tcp}]\nenable_motd = false\nbootstrap_nodes = ()\n",
        dir.join("keys").display(),
        dir.join("pid").display()
    );
    std::fs::write(&conf, text).ok()?;
    let mut child = Command::new("tox-bootstrapd")
        .arg(format!("--config={}", conf.display()))
        .args(["--foreground", "--log-backend=stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(key) = line.strip_prefix("Public Key: ") {
                let _ = tx.send(key.trim().to_string());
            }
        }
    });
    let key = rx.recv_timeout(Duration::from_secs(20)).expect("tox-bootstrapd said its key");
    let relay = Relay { child, dir, port: tcp, key };
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", tcp)).is_err() {
        assert!(Instant::now() < deadline, "tox-bootstrapd's TCP relay did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(relay)
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_the_tox_road() {
    let lab = Lab::new("tox");
    let (named, relay) = match std::env::var("PODSSH_TOX_TEST_RELAY") {
        Ok(named) => (named, None),
        Err(_) => {
            let Some(relay) = start(lab.node_home.join("tox")) else {
                eprintln!("did not run: no tox-bootstrapd here (apt install toxcore-utils)");
                return;
            };
            (format!("127.0.0.1:{}={}", relay.port, relay.key), Some(relay))
        }
    };
    let env = [("PODSSH_TOX", named.as_str())];
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
    wait_for(&lines, "waits for its operators on the Tox relay");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.envs(env.iter().copied()).env("PODSSH_DERP", "no");
    let began = Instant::now();
    let (rc, out, err) = run_within(&mut client, Duration::from_secs(90));
    let node_said: Vec<String> = lines.try_iter().collect();
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}; the node said: {node_said:#?}");
    assert_eq!(out, GREETING, "the command's output over the Tox road");
    assert!(err.contains("the Tox road answered first"), "{err}");
    eprintln!("podssh ssh node:// through the Tox road in {:.1} s", began.elapsed().as_secs_f64());
    drop(relay);
    drop(lab.runtime);
}
