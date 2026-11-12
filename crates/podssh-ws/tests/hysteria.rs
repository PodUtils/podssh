//! The Hysteria 2 road (T-580) against Hysteria's own server
//! (`apernet/hysteria`, MIT), a server that podssh did not write: the release
//! that `hysteria-interop.yml` pins and checks by its SHA-256, its path in
//! `PODSSH_HYSTERIA_TEST_BIN`, on the loopback, under a certificate that
//! `openssl` makes for each run. The target's version line and a large echo
//! come through it, with the link checked by a root, by a pin, and under
//! Salamander; a wrong password meets the server's web answer, any status but
//! 233, and the road is refused; a target that the server cannot reach is
//! refused with its words. These say "did not run" with no server, and the
//! workflow fails on it. A port that drops UDP makes the probe say so with no
//! wait for QUIC: that test needs no server, and runs in each build.

#![cfg(feature = "quic")]

mod vless_support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ws::hysteria::{self, Dial, HysteriaError, Opened, Server};
use podssh_ws::Trust;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vless_support::{pins, target, BANNER, NAME};

const LIMIT: Duration = Duration::from_secs(20);
/// The tests' own throwaway passwords, no credential.
const PASSWORD: &str = "hysteria-test-password";
const SALAMANDER: &str = "salamander-test-key";

/// Hysteria's server on the loopback; killed, and its directory gone, when
/// the test ends.
struct Hysteria {
    child: Child,
    dir: PathBuf,
    port: u16,
    /// The SHA-256 of the server's certificate, in hex.
    pin: String,
}

impl Drop for Hysteria {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(dir: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program).args(args).current_dir(dir).stdout(Stdio::null()).status();
    assert!(status.map(|s| s.success()).unwrap_or(false), "{program} {args:?} failed");
}

/// The server, with Salamander when `salamander`, or `None` (and the words
/// "did not run") with no binary.
async fn hysteria(tag: &str, salamander: bool) -> Option<Hysteria> {
    let Some(bin) = std::env::var_os("PODSSH_HYSTERIA_TEST_BIN") else {
        println!("did not run: PODSSH_HYSTERIA_TEST_BIN names no Hysteria (hysteria-interop.yml sets it)");
        return None;
    };
    let dir = std::env::temp_dir().join(format!("podssh-hysteria-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A root and a leaf, as the VMess test makes them: webpki takes no CA as
    // the server's own certificate.
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
    let subject = ["-subj", "/CN=hy-root"];
    let ca = [&["req", "-x509"][..], &ec, &["-keyout", "ca.key", "-out", "ca.pem", "-days", "2"], &subject];
    run(&dir, "openssl", &ca.concat());
    let csr = [&["req"][..], &ec, &["-keyout", "srv.key", "-out", "srv.csr", "-subj", &format!("/CN={NAME}")]];
    run(&dir, "openssl", &csr.concat());
    std::fs::write(dir.join("leaf.cnf"), format!("subjectAltName=DNS:{NAME}\nbasicConstraints=CA:FALSE\n")).unwrap();
    let sign = ["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out"];
    run(&dir, "openssl", &[&sign[..], &["srv.pem", "-days", "2", "-extfile", "leaf.cnf"]].concat());
    run(&dir, "openssl", &["x509", "-in", "srv.pem", "-outform", "der", "-out", "srv.der"]);
    let pin = hysteria::link::hex(&Sha256::digest(std::fs::read(dir.join("srv.der")).unwrap()));
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let obfs = match salamander {
        true => format!("obfs:\n  type: salamander\n  salamander:\n    password: {SALAMANDER}\n"),
        false => String::new(),
    };
    let (cert, key) = (dir.join("srv.pem"), dir.join("srv.key"));
    let tls = format!("tls:\n  cert: {}\n  key: {}\n", cert.display(), key.display());
    let auth = format!("auth:\n  type: password\n  password: {PASSWORD}\n");
    let config = format!("listen: 127.0.0.1:{port}\n{tls}{auth}{obfs}");
    std::fs::write(dir.join("config.yaml"), config).unwrap();
    let log = std::fs::File::create(dir.join("hysteria.log")).unwrap();
    let child = Command::new(bin)
        .args(["server", "--disable-update-check", "-c"])
        .arg(dir.join("config.yaml"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("Hysteria starts");
    let server = Hysteria { child, dir, port, pin };
    // It listens once the probe's packet gets its Version Negotiation.
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let key = salamander.then_some(SALAMANDER.as_bytes());
    let until = Instant::now() + LIMIT;
    loop {
        let probed = hysteria::probe::one(addr, key, Duration::from_millis(300)).await;
        if matches!(probed, Ok(Some(hysteria::probe::Probed::Answered(_)))) {
            return Some(server);
        }
        assert!(Instant::now() < until, "Hysteria did not answer the probe: {}", log_of(&server));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn log_of(server: &Hysteria) -> String {
    std::fs::read_to_string(server.dir.join("hysteria.log")).unwrap_or_default()
}

/// A link to the server: its query after `?`.
fn link(port: u16, password: &str, query: &str) -> Server {
    Server::parse(&format!("hysteria2://{password}@{NAME}:{port}/?{query}")).unwrap()
}

async fn open(server: &Hysteria, link: &Server, aim: u16) -> Result<Opened, HysteriaError> {
    let trust = Trust::File(server.dir.join("ca.pem"));
    let dial = Dial { trust: &trust, timeout: LIMIT, probe_wait: hysteria::probe::WAIT };
    tokio::time::timeout(LIMIT * 2, hysteria::open(link, "127.0.0.1", aim, &dial)).await.expect("within the limit")
}

/// `sent` echoed back, read while it goes.
async fn echoes(opened: &mut Opened, sent: &[u8]) {
    let mut back = vec![0u8; sent.len()];
    let (mut read, mut write) = tokio::io::split(&mut opened.stream);
    let up = async {
        write.write_all(sent).await.unwrap();
        write.flush().await.unwrap();
    };
    let both = async { tokio::join!(up, async { read.read_exact(&mut back).await.unwrap() }) };
    tokio::time::timeout(LIMIT * 2, both).await.expect("the echo within the limit");
    assert!(back == sent, "the bytes came back changed");
}

/// The target's version line, then 300 KB echoed whole: by the root of
/// `--ca-file`, by the pin of the certificate, and under Salamander.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_banner_and_an_echo_come_through_hysteria() {
    let Some(plain) = hysteria("plain", false).await else { return };
    let Some(salted) = hysteria("salted", true).await else { return };
    pins();
    let aim = target(true).await;
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let pinned = format!("insecure=1&pinSHA256={}", plain.pin);
    let salted_query = format!("obfs=salamander&obfs-password={SALAMANDER}&pinSHA256={}", salted.pin);
    for (what, server, query) in
        [("a root", &plain, String::new()), ("a pin", &plain, pinned), ("Salamander", &salted, salted_query)]
    {
        let link = link(server.port, PASSWORD, &query);
        let mut opened = open(server, &link, aim)
            .await
            .unwrap_or_else(|e| panic!("{what}: {}\n{}", e.line(&link.shown(), "target"), log_of(server)));
        let mut banner = vec![0u8; BANNER.len()];
        tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut banner)).await.unwrap().unwrap();
        assert_eq!(banner, BANNER, "{what}");
        echoes(&mut opened, &big).await;
    }
}

/// A wrong password meets the server's web answer (404 by default), any
/// status but 233; another pin, and another Salamander key, are refused too;
/// a target that nothing serves is refused with the server's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_a_wrong_pin_and_an_unreachable_target_are_refused() {
    let Some(plain) = hysteria("refused", false).await else { return };
    let Some(salted) = hysteria("refused-salted", true).await else { return };
    pins();
    let aim = target(true).await;
    match open(&plain, &link(plain.port, "not-the-password", ""), aim).await {
        Err(HysteriaError::Auth(status)) => assert_ne!(status, hysteria::AUTH_OK),
        Err(other) => panic!("a wrong password: {}", other.line("x", "t")),
        Ok(_) => panic!("a wrong password carried the session"),
    }
    let other_pin = format!("insecure=1&pinSHA256={}", "00".repeat(32));
    match open(&plain, &link(plain.port, PASSWORD, &other_pin), aim).await {
        Err(HysteriaError::Pin { seen, .. }) => assert_eq!(seen, plain.pin),
        Err(other) => panic!("another pin: {}", other.line("x", "t")),
        Ok(_) => panic!("another pin carried the session"),
    }
    let other_key = format!("obfs=salamander&obfs-password=another-key&pinSHA256={}", salted.pin);
    match open(&salted, &link(salted.port, PASSWORD, &other_key), aim).await {
        Err(HysteriaError::NoUdp(_)) => {}
        Err(other) => panic!("another Salamander key: {}", other.line("x", "t")),
        Ok(_) => panic!("another Salamander key carried the session"),
    }
    // A port of the loopback that nothing serves: bound, then let go.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    match open(&plain, &link(plain.port, PASSWORD, ""), closed).await {
        Err(HysteriaError::Refused(message)) => assert!(!message.is_empty()),
        Err(other) => panic!("an unreachable target: {}", other.line("x", "t")),
        Ok(_) => panic!("an unreachable target carried the session"),
    }
}

/// A stand-in that takes UDP and drops it: the probe says that UDP does
/// not pass within its wait, and no QUIC handshake waits its 5 s.
#[tokio::test]
async fn a_port_that_drops_udp_ends_the_road_at_the_probe() {
    pins();
    let drops = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let link = link(drops.local_addr().unwrap().port(), PASSWORD, "");
    let trust = Trust::Default;
    let wait = Duration::from_millis(600);
    let dial = Dial { trust: &trust, timeout: LIMIT, probe_wait: wait };
    let started = Instant::now();
    let failed = match hysteria::open(&link, "127.0.0.1", 22, &dial).await {
        Err(e) => e,
        Ok(_) => panic!("a port that drops UDP carried a session"),
    };
    let took = started.elapsed();
    assert!(matches!(failed, HysteriaError::NoUdp(_)), "{failed:?}");
    assert!(took >= wait && took < Duration::from_secs(3), "the road ended after {took:?}");
    let line = failed.line(&link.shown(), "127.0.0.1:22");
    assert!(line.starts_with("UDP does not reach the Hysteria 2 server") && !line.contains(PASSWORD), "{line}");
    drop(drops);
}
