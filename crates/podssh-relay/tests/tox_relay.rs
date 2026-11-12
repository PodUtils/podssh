//! A client of Tox's TCP relay against c-toxcore's own relay (T-734):
//! `tox-bootstrapd` with its TCP relay on a port of the loopback, two
//! clients with fresh keys that each route to the other, and 1 MiB from one
//! to the other, its digest equal; then a route to a key that never comes,
//! which connects nothing within its limit. The check says that it did not
//! run when this host has no `tox-bootstrapd` (`apt install toxcore-utils`).
#![cfg(feature = "tox")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::tox::routed::meet;
use podssh_relay::tox::wire::{connect, Keys, KEY};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(20);

/// c-toxcore's relay, ended when this drops.
struct Relay {
    child: Child,
    dir: std::path::PathBuf,
    port: u16,
    key: [u8; KEY],
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    // A port that the system gave a moment ago; the relay binds it next.
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).expect("a free port")
}

fn hex_key(text: &str) -> Option<[u8; KEY]> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| text.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}

/// `tox-bootstrapd` in the foreground, its TCP relay on a free port, once it
/// said its key; `None` where this host has none.
fn start() -> Option<Relay> {
    let dir = std::env::temp_dir().join(format!("podssh-tox-{}-{}", std::process::id(), free_port()));
    std::fs::create_dir_all(&dir).ok()?;
    let (udp, tcp) = (free_port(), free_port());
    let conf = dir.join("conf");
    std::fs::write(
        &conf,
        format!(
            "port = {udp}\nkeys_file_path = \"{}\"\npid_file_path = \"{}\"\nenable_ipv6 = false\n\
             enable_ipv4_fallback = true\nenable_lan_discovery = false\nenable_tcp_relay = true\n\
             tcp_relay_ports = [{tcp}]\nenable_motd = false\nbootstrap_nodes = ()\n",
            dir.join("keys").display(),
            dir.join("pid").display()
        ),
    )
    .ok()?;
    let spawned = Command::new("tox-bootstrapd")
        .arg(format!("--config={}", conf.display()))
        .args(["--foreground", "--log-backend=stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(_) => {
            eprintln!("did not run: no tox-bootstrapd here (apt install toxcore-utils)");
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
    };
    let out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(key) = line.strip_prefix("Public Key: ").and_then(|k| hex_key(k.trim())) {
                let _ = tx.send(key);
            }
        }
    });
    let key = rx.recv_timeout(LIMIT).expect("tox-bootstrapd said its key");
    let relay = Relay { child, dir, port: tcp, key };
    let deadline = Instant::now() + LIMIT;
    while std::net::TcpStream::connect(("127.0.0.1", tcp)).is_err() {
        assert!(Instant::now() < deadline, "tox-bootstrapd's TCP relay did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(relay)
}

#[tokio::test]
async fn two_clients_meet_on_c_toxcore_s_relay_and_carry_a_mib_whole() {
    let Some(relay) = start() else { return };
    let (a, b) = (Keys::fresh(), Keys::fresh());
    let (a_key, b_key) = (a.public(), b.public());
    let dial = |keys: Keys| {
        let (port, key) = (relay.port, relay.key);
        async move {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("the relay's port");
            let (read, write) = tcp.into_split();
            connect(read, write, &key, &keys).await.expect("the relay's handshake")
        }
    };
    let (a_conn, b_conn) = tokio::join!(dial(a), dial(b));
    let (a_stream, b_stream) =
        tokio::join!(meet(a_conn.0, a_conn.1, b_key, LIMIT), meet(b_conn.0, b_conn.1, a_key, LIMIT));
    let (mut a_stream, mut b_stream) = (a_stream.expect("a met b"), b_stream.expect("b met a"));
    let bytes: Vec<u8> = (0..1u32 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
    let sent = Sha256::digest(&bytes);
    let writer = tokio::spawn(async move {
        a_stream.write_all(&bytes).await.expect("a writes");
        a_stream
    });
    let mut got = Vec::with_capacity(1 << 20);
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + LIMIT;
    while got.len() < 1 << 20 {
        match tokio::time::timeout_at(deadline, b_stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert_eq!(got.len(), 1 << 20, "the MiB came within {LIMIT:?}");
    assert_eq!(Sha256::digest(&got), sent, "the MiB came whole");
    drop(writer.await);
}

#[tokio::test]
async fn a_route_to_a_key_that_never_comes_connects_nothing() {
    let Some(relay) = start() else { return };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", relay.port)).await.expect("the relay's port");
    let (read, write) = tcp.into_split();
    let (sender, receiver) = connect(read, write, &relay.key, &Keys::fresh()).await.expect("the handshake");
    let met = meet(sender, receiver, Keys::fresh().public(), Duration::from_secs(2)).await;
    assert_eq!(met.err().map(|e| e.kind()), Some(std::io::ErrorKind::TimedOut));
}

#[tokio::test]
async fn a_relay_of_another_key_is_refused_at_its_answer() {
    let Some(relay) = start() else { return };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", relay.port)).await.expect("the relay's port");
    let (read, write) = tcp.into_split();
    let wrong = Keys::fresh().public();
    let answer = tokio::time::timeout(Duration::from_secs(5), connect(read, write, &wrong, &Keys::fresh())).await;
    // The relay cannot open a hello to another key: it closes, or says nothing.
    assert!(!matches!(answer, Ok(Ok(_))), "a handshake with the wrong key of the relay passed");
}
