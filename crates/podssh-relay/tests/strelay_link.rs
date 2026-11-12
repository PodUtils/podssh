//! Syncthing's relay road against Syncthing's own relay (T-571):
//! `strelaysrv` of a pinned release, on a port of the loopback, joined to no
//! pool; its device ID is the SHA-256 of the certificate that it writes. A
//! node of a pair joins it; a client of the pair asks for the node's device
//! ID, joins the session, and a MiB goes up and comes back whole (the relay
//! passes no half-close, so the stream has no end of its own); a client
//! that asks for another device ID gets no session. The relay is
//! `PODSSH_STRELAY_TEST_BIN`, or `strelaysrv` on the PATH; the check says
//! that it did not run where there is none.
#![cfg(feature = "strelay")]

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use podssh_relay::strelay::cert::device_id;
use podssh_relay::strelay::pair::{self, link, node_identity, BoxIo, Dial, Relay};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The relay, ended when this drops.
struct Strelay {
    child: Child,
    dir: std::path::PathBuf,
    relay: Relay,
}

impl Drop for Strelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(name: &str) -> Option<Strelay> {
    let bin = std::env::var("PODSSH_STRELAY_TEST_BIN").unwrap_or_else(|_| "strelaysrv".into());
    let dir = std::env::temp_dir().join(format!("podssh-strelay-{name}-{}", std::process::id()));
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
    let der = base64::engine::general_purpose::STANDARD.decode(b64).expect("the relay's certificate");
    let relay = Relay { ip: IpAddr::from([127, 0, 0, 1]), port, id: device_id(&der) };
    Some(Strelay { child, dir, relay })
}

fn direct() -> Dial {
    Arc::new(|ip, port| {
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect((ip, port)).await?;
            Ok(Box::new(tcp) as BoxIo)
        })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_s_node_and_its_client_meet_on_syncthing_s_relay_and_carry_a_mib_whole() {
    let Some(relay) = start("pair") else {
        eprintln!("did not run: no strelaysrv here (PODSSH_STRELAY_TEST_BIN, or strelaysrv on the PATH)");
        return;
    };
    let me = node_identity("lab", "token-1");
    let node_id = me.id();
    let (visitors, mut came) = tokio::sync::mpsc::channel::<BoxIo>(4);
    let (lines, mut said) = tokio::sync::mpsc::unbounded_channel::<String>();
    let say: pair::Say = Arc::new(move |line| {
        let _ = lines.send(line);
    });
    tokio::spawn(pair::serve(direct(), relay.relay, me, visitors, say));
    let joined = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = said.recv().await {
            if line.contains("waits for its operators") {
                return;
            }
        }
    });
    joined.await.expect("the node joined the relay");
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
    let stream = link(&direct(), &relay.relay, node_id, Duration::from_secs(20)).await.expect("a session to the node");
    let sent: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8).collect();
    let (mut r, mut w) = tokio::io::split(stream);
    let up = sent.clone();
    // The relay passes no half-close (it copies until a side closes), so the
    // echo comes back whole with no end of its own.
    let writing = tokio::spawn(async move {
        w.write_all(&up).await.unwrap();
        w
    });
    let mut back = vec![0u8; sent.len()];
    tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut back)).await.expect("the echo").unwrap();
    drop(writing.await.unwrap());
    assert_eq!(back.len(), sent.len());
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "the MiB came back changed");
    eprintln!("1 MiB up and back through Syncthing's relay in {:?}", began.elapsed());
    // A device ID that no node holds: no session.
    let other = node_identity("lab", "token-2").id();
    let refused = link(&direct(), &relay.relay, other, Duration::from_secs(20)).await.err().expect("no session");
    assert_eq!(refused.kind(), std::io::ErrorKind::NotFound, "{refused}");
}
