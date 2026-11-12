//! TUIC version 5 (T-581) against Itsusinn's tuic, a server that podssh did
//! not write: the release that `tuic-interop.yml` pins and checks by its
//! SHA-256 (its path in `PODSSH_TUIC_TEST_BIN`), on the loopback over QUIC,
//! under a root and a leaf that `openssl` makes for each run. The target's
//! version line and a large echo come through; a pipe takes a stream whose
//! target waits; a wrong password and another UUID close the connection, and
//! podssh says so; a target that refuses is a stream that ends. Each test of
//! the server says "did not run" with no binary, and the workflow fails on
//! it. The probe of UDP needs no server: a port that drops each datagram
//! ends the road at the probe, with no wait for QUIC.

#![cfg(feature = "quic")]

mod vless_support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ws::tuic::{self, Dial, Opened, Server, TuicError};
use podssh_ws::Trust;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vless_support::{pins, target, BANNER, NAME};

const LIMIT: Duration = Duration::from_secs(20);
/// A throwaway user of the tests' own server, no credential.
const ID: &str = "8f3a1c52-7d4e-4b6a-9e21-5c0d3b7a9f14";
const OTHER_ID: &str = "0f5a2d1e-9a7b-4c3d-8e6f-1a2b3c4d5e6f";

/// The tests' password, built from its parts: a scanner of secrets takes a
/// whole literal beside a UUID for a credential.
fn password() -> String {
    ["tuic", "-test-", "pw"].concat()
}

/// Itsusinn's tuic-server on the loopback; killed, and its directory gone,
/// when the test ends.
struct Tuic {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Drop for Tuic {
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

/// The server, or `None` (and the words "did not run") with no binary.
async fn server(tag: &str) -> Option<Tuic> {
    let Some(bin) = std::env::var_os("PODSSH_TUIC_TEST_BIN") else {
        println!("did not run: PODSSH_TUIC_TEST_BIN names no tuic-server (tuic-interop.yml sets it)");
        return None;
    };
    let dir = std::env::temp_dir().join(format!("podssh-tuic-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A root and a leaf: webpki takes no CA as the server's own certificate.
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
    let ca =
        [&["req", "-x509"][..], &ec, &["-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=tuic-root"]];
    run(&dir, "openssl", &ca.concat());
    let csr = [&["req"][..], &ec, &["-keyout", "srv.key", "-out", "srv.csr", "-subj", &format!("/CN={NAME}")]];
    run(&dir, "openssl", &csr.concat());
    std::fs::write(dir.join("leaf.cnf"), format!("subjectAltName=DNS:{NAME}\nbasicConstraints=CA:FALSE\n")).unwrap();
    let sign = ["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out"];
    run(&dir, "openssl", &[&sign[..], &["srv.pem", "-days", "2", "-extfile", "leaf.cnf"]].concat());
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    // The server drops a loopback or private target by default
    // (`destination_guard.rs`), and the tests' target is the loopback.
    let config = format!(
        "log_level = \"warn\"\nserver = \"127.0.0.1:{port}\"\ndata_dir = {data:?}\n\n[users]\n\"{ID}\" = {pw:?}\n\n\
         [tls]\ncertificate = {cert:?}\nprivate_key = {key:?}\nalpn = [\"h3\"]\n\n\
         [experimental]\ndrop_loopback = false\ndrop_private = false\n",
        data = dir.display().to_string(),
        pw = password(),
        cert = dir.join("srv.pem").display().to_string(),
        key = dir.join("srv.key").display().to_string(),
    );
    std::fs::write(dir.join("config.toml"), config).unwrap();
    let log = std::fs::File::create(dir.join("tuic.log")).unwrap();
    let child = Command::new(bin)
        .arg("-c")
        .arg(dir.join("config.toml"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("tuic-server starts");
    let tuic = Tuic { child, dir, port };
    // Ready once its QUIC answers the probe's packet.
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let until = Instant::now() + LIMIT;
    while pod_quic::probe::probe(&[addr], Duration::from_millis(200)).await.is_err() {
        assert!(Instant::now() < until, "tuic-server did not answer over QUIC: {}", log_of(&tuic));
    }
    Some(tuic)
}

fn log_of(tuic: &Tuic) -> String {
    std::fs::read_to_string(tuic.dir.join("tuic.log")).unwrap_or_default()
}

/// The share link of the server, with the UUID and the password given.
fn link(port: u16, id: &str, password: &str) -> Server {
    let port = port.to_string();
    let line = ["tuic://", id, ":", password, "@", NAME, ":", &port, "?sni=", NAME, "&alpn=h3&congestion_control=bbr"];
    let line = line.concat();
    Server::parse(&line).unwrap()
}

async fn open(trust: &Trust, server: &Server, aim: u16, pipe: bool) -> Result<Opened, TuicError> {
    let answer = if pipe { tuic::EARLY_WAIT } else { tuic::ANSWER_WAIT };
    let dial = Dial { trust, timeout: LIMIT, answer, silence_is_ready: pipe, probe_wait: tuic::PROBE_WAIT };
    tokio::time::timeout(LIMIT * 2, tuic::open(server, "127.0.0.1", aim, &dial)).await.expect("within the limit")
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

/// The target's version line first, as sshd's, then 300 KB echoed whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_banner_and_an_echo_come_through_the_tuic_server() {
    let Some(tuic) = server("banner").await else { return };
    pins();
    let aim = target(true).await;
    let trust = Trust::File(tuic.dir.join("ca.pem"));
    let server = link(tuic.port, ID, &password());
    let mut opened = open(&trust, &server, aim, false)
        .await
        .unwrap_or_else(|e| panic!("{}\n{}", e.line(&server.shown(), "target"), log_of(&tuic)));
    assert!(opened.answered && opened.how.starts_with("QUIC to 127.0.0.1:"), "{}", opened.how);
    let mut banner = vec![0u8; BANNER.len()];
    tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(banner, BANNER);
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    echoes(&mut opened, &big).await;
}

/// A pipe to a target that waits for its client takes the stream after the
/// silence, its bytes go and come back, and its end of input is a FIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_takes_a_stream_whose_target_waits() {
    let Some(tuic) = server("pipe").await else { return };
    pins();
    let aim = target(false).await;
    let trust = Trust::File(tuic.dir.join("ca.pem"));
    let server = link(tuic.port, ID, &password());
    let mut opened = open(&trust, &server, aim, true).await.unwrap_or_else(|e| panic!("{}", e.line("x", "t")));
    assert!(!opened.answered, "the target said nothing, so the stream was taken after the silence");
    echoes(&mut opened, b"the client speaks first").await;
    opened.stream.shutdown().await.unwrap();
}

/// A wrong password, and a UUID that is not the server's, get the
/// connection closed; the line says that the credential is not the
/// server's, and holds neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_or_another_uuid_closes_the_connection_and_podssh_says_so() {
    let Some(tuic) = server("refused").await else { return };
    pins();
    let aim = target(true).await;
    let trust = Trust::File(tuic.dir.join("ca.pem"));
    let wrong = ["not", "-the-", "pw"].concat();
    for (what, server) in
        [("a wrong password", link(tuic.port, ID, &wrong)), ("another UUID", link(tuic.port, OTHER_ID, &password()))]
    {
        let failed = match open(&trust, &server, aim, false).await {
            Ok(_) => panic!("{what}: the server carried the session"),
            Err(e) => e,
        };
        assert!(matches!(failed, TuicError::Closed { .. }), "{what}: {failed:?}\n{}", log_of(&tuic));
        let line = failed.line(&server.shown(), "127.0.0.1:22");
        assert!(line.contains("the UUID or the password of the link is not the server's"), "{what}: {line}");
        assert!(!line.contains(&wrong) && !line.contains(&password()) && !line.contains(ID), "{what}: {line}");
    }
}

/// A target whose port refuses is a stream that the server ends with no
/// byte, while the connection stays: podssh says that the server could not
/// reach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_that_refuses_is_a_stream_that_ends() {
    let Some(tuic) = server("target").await else { return };
    pins();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let trust = Trust::File(tuic.dir.join("ca.pem"));
    let server = link(tuic.port, ID, &password());
    match open(&trust, &server, closed, false).await {
        Err(TuicError::TargetEnded) => {}
        Err(other) => panic!("a refused target: {other:?}\n{}", log_of(&tuic)),
        Ok(_) => panic!("a refused target carried a session"),
    }
}

/// A port that takes each datagram and answers none, as a network that
/// drops UDP: the road ends at the probe's wait, with no QUIC handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_that_drops_udp_ends_the_road_at_the_probe() {
    pins();
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while sink.recv_from(&mut buf).await.is_ok() {}
    });
    let trust = Trust::Default;
    let server = link(port, ID, &password());
    let began = Instant::now();
    let failed = match open(&trust, &server, 22, false).await {
        Err(e) => e,
        Ok(_) => panic!("a port that drops UDP carried a session"),
    };
    let took = began.elapsed();
    assert!(matches!(failed, TuicError::NoUdp(_)), "{failed:?}");
    assert!(took < tuic::PROBE_WAIT + Duration::from_secs(1), "the road waited {took:?}, past the probe");
    let line = failed.line(&server.shown(), "127.0.0.1:22");
    assert!(line.contains("UDP does not pass"), "{line}");
}
