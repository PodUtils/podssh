//! Yggdrasil's road against yggdrasil-go's own node (T-735): `yggdrasil` of
//! a pinned release, its link on `ws://` on the loopback, no TUN, no admin
//! socket and no multicast; two of podssh's routers peer with it, each
//! through its WebSocket and `meta` handshake, and reach each other by
//! their keys across it, Ironwood finding the path. The node is named by
//! `PODSSH_YGG_TEST_BIN`, or found as `yggdrasil` on the PATH; the check
//! says that it did not run where there is none.
#![cfg(feature = "yggdrasil")]

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use podssh_relay::ygg::link::{self, Peer};
use podssh_relay::ygg::router::{Router, Say};
use podssh_ws::{ProxyChoice, Trust};

const LIMIT: Duration = Duration::from_secs(30);

/// yggdrasil-go's node, ended when this drops.
pub struct Node {
    child: Child,
    dir: std::path::PathBuf,
    pub peer: Peer,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).expect("a free port")
}

/// The node, listening on `ws://` once its port answers; `None` with no
/// `yggdrasil` here.
pub fn start(name: &str) -> Option<Node> {
    let bin = std::env::var("PODSSH_YGG_TEST_BIN").unwrap_or_else(|_| "yggdrasil".into());
    let made = Command::new(&bin).args(["-genconf", "-json"]).stderr(Stdio::null()).output().ok()?;
    let mut conf: serde_json::Value = serde_json::from_slice(&made.stdout).ok()?;
    let port = free_port();
    conf["Listen"] = serde_json::json!([format!("ws://127.0.0.1:{port}")]);
    conf["MulticastInterfaces"] = serde_json::json!([]);
    conf["IfName"] = serde_json::json!("none");
    conf["AdminListen"] = serde_json::json!("none");
    let dir = std::env::temp_dir().join(format!("podssh-ygg-{name}-{}", std::process::id()));
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
    let node = Node { child, dir, peer: Peer::parse(&format!("ws://127.0.0.1:{port}/")).ok()? };
    let deadline = Instant::now() + LIMIT;
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "yggdrasil did not listen on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(node)
}

pub fn quiet() -> Say {
    Arc::new(|line| eprintln!("router: {line}"))
}

/// A router with a fresh key, linked to `peer`.
pub fn router(peer: &Peer) -> Arc<Router> {
    let router = Router::new(SigningKey::from_bytes(&rand::random()));
    let dial = link::dial(Trust::Default, ProxyChoice::Direct);
    tokio::spawn(router.clone().peer(peer.clone(), dial, quiet()));
    router
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_routers_reach_each_other_by_key_through_yggdrasil_go_s_node() {
    let Some(node) = start("reach") else {
        eprintln!("did not run: no yggdrasil here (PODSSH_YGG_TEST_BIN, or yggdrasil on the PATH)");
        return;
    };
    let (a, b) = (router(&node.peer), router(&node.peer));
    let began = Instant::now();
    // Ironwood drops what it cannot place yet: send again until it arrives.
    let sender = a.clone();
    let to = b.key();
    let sending = tokio::spawn(async move {
        loop {
            let _ = sender.send(&to, b"podssh over Yggdrasil").await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
    let mut buf = vec![0u8; 2048];
    let got = tokio::time::timeout(LIMIT, b.recv(&mut buf)).await.expect("a packet within the limit");
    sending.abort();
    let (n, from) = got.expect("the router is open");
    assert_eq!((&buf[..n], from), (&b"podssh over Yggdrasil"[..], a.key()));
    eprintln!("the first packet from one router to the other in {:?}", began.elapsed());
    // And back, now that each knows the other's path.
    a.send(&b.key(), b"x").await.unwrap();
    b.send(&a.key(), b"and back").await.unwrap();
    let (n, from) = loop {
        let got = tokio::time::timeout(LIMIT, a.recv(&mut buf)).await.expect("the answer").expect("open");
        if got.1 == b.key() {
            break got;
        }
    };
    assert_eq!((&buf[..n], from), (&b"and back"[..], b.key()));
    a.close().await;
    b.close().await;
    drop(node);
}

/// A pair's node and its client meet through the node of yggdrasil-go, and
/// a MiB goes up and comes back whole; a client with another token opens
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_s_node_echoes_a_mib_to_its_client_and_refuses_another_token() {
    use podssh_relay::ygg::pair::{node_secret, Ends, Serve};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(node) = start("pair") else {
        eprintln!("did not run: no yggdrasil here (PODSSH_YGG_TEST_BIN, or yggdrasil on the PATH)");
        return;
    };
    let secret = node_secret("lab", "token-1");
    let server = Router::new(secret.clone());
    tokio::spawn(server.clone().peer(node.peer.clone(), link::dial(Trust::Default, ProxyChoice::Direct), quiet()));
    let (visitors, mut came) = tokio::sync::mpsc::channel(4);
    Ends::start(server.clone(), Some(Serve { token: "token-1".into(), visitors }));
    // The node echoes each session.
    tokio::spawn(async move {
        while let Some(stream) = came.recv().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let client = Ends::start(router(&node.peer), None);
    let began = Instant::now();
    let stream = client.link(secret.verifying_key().to_bytes(), "token-1", LIMIT).await.expect("the node's welcome");
    eprintln!("the session opened in {:?}", began.elapsed());
    let sent: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
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
    // Another token proves nothing: no welcome.
    let other = client.link(secret.verifying_key().to_bytes(), "token-2", Duration::from_secs(4)).await;
    assert_eq!(other.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    drop(node);
}
