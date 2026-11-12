//! Syncthing's relay road beside a `--derp` node's own pair (T-571), with the
//! feature `strelay`: the node holds a pair whose relay is down, and serves
//! the DERP road with Syncthing's relay road beside it, joined to Syncthing's
//! own `strelaysrv` (`PODSSH_SYNCTHING_RELAY` names it) under the certificate
//! that the pair's secret makes; a client of the same pair, with its DERP road
//! off and the pair's road down, reaches the node through that relay alone.
//! The relay is `PODSSH_STRELAY_TEST_BIN`, or `strelaysrv` on the PATH; the
//! check says that it did not run where there is none. With
//! `PODSSH_STRELAY_TEST_RELAY=relay://IP:PORT/?id=ID`, the two ends meet on
//! that relay in its place: the short live run through one of the pool's;
//! with `list`, on the relay that podssh's list of services gives the pair.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::derp_croc::store_pair;
use crate::{lines_of, run_within, wait_for, Lab, Node, GREETING};

/// The relay, ended when this drops.
struct Strelay {
    child: Child,
    dir: std::path::PathBuf,
    url: String,
}

impl Drop for Strelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A device ID as Syncthing writes it: base32 with a Luhn check after each 13.
fn device_text(id: &[u8]) -> String {
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut acc, mut bits, mut text) = (0u32, 0u32, Vec::new());
    for b in id {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(B32[((acc >> bits) & 31) as usize]);
        }
    }
    text.push(B32[((acc << (5 - bits)) & 31) as usize]);
    let mut out = Vec::new();
    for group in text.chunks(13) {
        let (mut factor, mut sum) = (1usize, 0usize);
        for c in group {
            let addend = factor * B32.iter().position(|x| x == c).unwrap();
            factor = if factor == 2 { 1 } else { 2 };
            sum += addend / 32 + addend % 32;
        }
        out.extend_from_slice(group);
        out.push(B32[(32 - sum % 32) % 32]);
    }
    String::from_utf8(out).unwrap()
}

fn start(dir: std::path::PathBuf) -> Option<Strelay> {
    let bin = std::env::var("PODSSH_STRELAY_TEST_BIN").unwrap_or_else(|_| "strelaysrv".into());
    std::fs::create_dir_all(&dir).ok()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).ok()?.port();
    let child = Command::new(&bin)
        .args(["-listen", &format!("127.0.0.1:{port}"), "-pools", "", "-status-srv", "", "-nat=false"])
        .arg("-keys")
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let cert = loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("cert.pem")) {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break text;
            }
        }
        assert!(Instant::now() < deadline, "strelaysrv did not listen on {port}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let b64: String = cert.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let url = format!("relay://127.0.0.1:{port}/?id={}", device_text(&Sha256::digest(&der)));
    Some(Strelay { child, dir, url })
}

#[test]
fn a_derp_node_with_a_pair_serves_a_client_through_syncthing_s_relay() {
    let lab = Lab::new("strelay");
    let (named, relay) = match std::env::var("PODSSH_STRELAY_TEST_RELAY") {
        Ok(named) => (named, None),
        Err(_) => {
            let Some(relay) = start(lab.node_home.join("strelay")) else {
                eprintln!("did not run: no strelaysrv here (PODSSH_STRELAY_TEST_BIN, or strelaysrv on the PATH)");
                return;
            };
            (relay.url.clone(), Some(relay))
        }
    };
    // `list`: no relay named, so both ends take the relay of the pair's name
    // from podssh's list of services, as a user's run does.
    let env: Vec<(&str, &str)> =
        if named == "list" { Vec::new() } else { vec![("PODSSH_SYNCTHING_RELAY", named.as_str())] };
    lab.let_in();
    store_pair(&lab.node_home);
    store_pair(&lab.client_home);
    let (key, allow, servers) =
        (lab.node_home.join("node.key"), lab.allow.to_string_lossy().into_owned(), lab.servers());
    let key = key.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--allow", &allow, "--key", &key, "--ca-file", &lab.ca, "--derp"];
    let mut cmd = crate::command(&lab.node_home, &words);
    cmd.args(["--derp-server", &servers]).envs(env.iter().copied());
    // The lab's command turns the road off; `list` turns it on with no relay named.
    if named == "list" {
        cmd.env_remove("PODSSH_SYNCTHING_RELAY");
    }
    let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    let _node = Node(child);
    wait_for(&lines, "ticket derp:");
    wait_for(&lines, "waits for its operators on Syncthing's relay");

    let mut client = lab.ssh(&["-v", "--derp-server", &servers, "node://tester@lab", "greet"]);
    client.envs(env.iter().copied()).env("PODSSH_DERP", "no");
    if named == "list" {
        client.env_remove("PODSSH_SYNCTHING_RELAY");
    }
    let began = Instant::now();
    let (rc, out, err) = run_within(&mut client, Duration::from_secs(90));
    let node_said: Vec<String> = lines.try_iter().collect();
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}; the node said: {node_said:#?}");
    assert_eq!(out, GREETING, "the command's output over Syncthing's relay road");
    assert!(err.contains("Syncthing's relay road answered first"), "{err}");
    eprintln!("podssh ssh node:// through Syncthing's relay road in {:.1} s", began.elapsed().as_secs_f64());
    drop(relay);
    drop(lab.runtime);
}
