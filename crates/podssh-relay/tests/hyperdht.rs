//! HyperDHT's road against the `hyperdht` package of Node.js (T-736), software
//! that podssh did not write: a private DHT of three nodes on the loopback
//! (`tests/hyperdht/testnet.js`, a pinned 6.x release), where a node of a
//! pair announces the topic of its key and a client of the pair connects by
//! that key and gets a MiB echoed whole; and a bootstrap that never answers,
//! which the road reads as UDP that does not pass. The package's directory
//! is `PODSSH_HYPERDHT_TEST_NODE_PATH` (its `node_modules`); the check says
//! that it did not run where there is none, or no `node`. Run with
//! `--test-threads=1`: the private DHT takes its fixed port.
#![cfg(feature = "hyperdht")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::hyperdht::{join, node_keys};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The private DHT, ended when this drops (its stdin closes).
struct Testnet {
    child: Child,
    bootstrap: Vec<String>,
}

impl Drop for Testnet {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn testnet() -> Option<Testnet> {
    let modules = std::env::var("PODSSH_HYPERDHT_TEST_NODE_PATH").ok()?;
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/hyperdht/testnet.js");
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
    Some(Testnet { child, bootstrap })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_s_node_and_its_client_meet_by_key_and_carry_a_mib_whole() {
    let Some(net) = testnet() else {
        eprintln!("did not run: no hyperdht package here (PODSSH_HYPERDHT_TEST_NODE_PATH) or no node");
        return;
    };
    let keys = node_keys("lab", "token-1");
    let node_key = keys.public_key;
    let node = join(&net.bootstrap, Some(keys)).await.expect("the node joins the private DHT");
    let (visitors, mut came) = tokio::sync::mpsc::channel(4);
    tokio::spawn(node.serve(visitors, std::sync::Arc::new(|line| eprintln!("node: {line}"))));
    tokio::spawn(async move {
        while let Some(stream) = came.recv().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let began = Instant::now();
    let mut client = join(&net.bootstrap, None).await.expect("the client joins the private DHT");
    let stream = client.link(node_key, Duration::from_secs(60)).await.expect("the node by its key");
    eprintln!("the session opened in {:?}", began.elapsed());
    let sent: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let (mut r, mut w) = tokio::io::split(stream);
    let up = sent.clone();
    let writing = tokio::spawn(async move {
        w.write_all(&up).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut back = Vec::new();
    tokio::time::timeout(Duration::from_secs(120), r.read_to_end(&mut back))
        .await
        .expect("the echo within 120 s")
        .unwrap();
    writing.await.unwrap();
    assert_eq!(back.len(), sent.len());
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "the MiB came back changed");
    eprintln!("1 MiB up and back in {:?}", began.elapsed());
    drop(net);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bootstrap_that_never_answers_is_udp_that_does_not_pass() {
    // A port that the system gave and took back: no DHT answers there.
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let refused = join(&[format!("127.0.0.1:{port}")], None).await.err().expect("no DHT");
    assert!(refused.to_string().contains("UDP did not pass"), "{refused}");
}
