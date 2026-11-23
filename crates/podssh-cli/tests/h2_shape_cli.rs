//! `--h2-shape` on a session that the CLI opens (T-763): `podssh proxy`
//! through the shape's HTTP/2 road to an echo behind a real `podssh relay
//! serve`, with an edge of the test in front of the role.
//!
//! The edge terminates TLS for the relay's name with a CA of its own, which
//! podssh trusts (`--ca-file`), and it carries each byte to the role over a
//! TLS of its own: it is a proxy that ends TLS, and podssh reaches it as it
//! reaches any relay host. On a connection that chose `h2` by ALPN, the edge
//! keeps the client's preface and its first frame, the SETTINGS frame; then
//! it carries the connection to the role unchanged, so the session is the
//! role's own. The role mints for anyone and dials the loopback. The
//! resumable layer is off (`PODSSH_RELAY_LAYER=no`), as in `h2_each_cli`:
//! the layer keeps its own upgrade, and this test is about the road of the
//! contract.
//!
//! Two runs, one shape each, to the same role and the same echo: each carries
//! its bytes back whole, the role answers each on `h2`, and the SETTINGS that
//! the edge kept are the shape's own bytes, different for the two. A run
//! that chose no shape calls `podssh_relay::open` as before T-763; a run
//! that named one opens its session on `podssh_ws::h2_road`, which is the
//! only road that sends the shape.
//!
//!     cargo test -p podssh-cli --test h2_shape_cli

mod cloud_support;
mod http_road_cli_support;
mod ssh_harness;
mod throughput_harness;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_road_cli_support::{bytes, role_certificate, run, Ran, NAME};
use podssh_ws::Trust;
use rustls::pki_types::ServerName;
use throughput_harness::{without_proxy, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Each run sends this and asks for it back.
const SIZE: usize = 64 * 1024;
/// The bound of each wait of the setup.
const WAIT: Duration = Duration::from_secs(30);

/// What one connection of the edge saw: the ALPN that it chose, and, on
/// `h2`, the client's preface and first frame.
#[derive(Clone, Default)]
struct Kept {
    alpn: Option<Vec<u8>>,
    first: Vec<u8>,
}

/// The edge: its port, and each connection's record in the order taken.
struct Edge {
    port: u16,
    kept: Arc<Mutex<Vec<Kept>>>,
    /// The edge's runtime: its tasks end with it.
    _rt: tokio::runtime::Runtime,
}

impl Edge {
    /// An edge on the loopback in front of `role`, presenting `cert` and
    /// `key` (a leaf of the CA that podssh is given) and trusting the role's
    /// certificate by `role_ca`.
    fn start(role: u16, cert: &Path, key: &Path, role_ca: &Path) -> Edge {
        let acceptor = podssh_ws::tls_server::acceptor(
            &std::fs::read(cert).expect("the edge's certificate"),
            &std::fs::read(key).expect("the edge's key"),
            &[b"h2", b"http/1.1"],
        )
        .expect("the edge's TLS");
        let role_ca = role_ca.to_path_buf();
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
        let kept: Arc<Mutex<Vec<Kept>>> = Arc::default();
        let port = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let kept = kept.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (acceptor, kept, role_ca) = (acceptor.clone(), kept.clone(), role_ca.clone());
                    tokio::spawn(async move {
                        let _ = carry(tcp, acceptor, role, role_ca, kept).await;
                    });
                }
            });
            port
        });
        Edge { port, kept, _rt: rt }
    }

    /// The connections that chose `h2`, in the order taken.
    fn h2(&self) -> Vec<Kept> {
        self.kept.lock().unwrap().iter().filter(|k| k.alpn.as_deref() == Some(b"h2")).cloned().collect()
    }
}

/// TLS for the client's name, then the role over TLS of the edge's own: the
/// bytes both ways, and on `h2` the preface and first frame kept.
async fn carry(
    tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    role: u16,
    role_ca: PathBuf,
    kept: Arc<Mutex<Vec<Kept>>>,
) -> std::io::Result<()> {
    let mut client = acceptor.accept(tcp).await.map_err(|e| std::io::Error::other(e.to_string()))?;
    let alpn = client.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let client_config =
        podssh_ws::tls::config_for(&Trust::File(role_ca)).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut config = (*client_config).clone();
    config.alpn_protocols = alpn.iter().cloned().collect();
    let up = TcpStream::connect(("127.0.0.1", role)).await?;
    let name = ServerName::try_from(NAME.to_string()).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut upstream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, up)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut first = Vec::new();
    if alpn.as_deref() == Some(b"h2") {
        // The preface, then the frame header and the frame that it lengths:
        // the client's SETTINGS is its first frame (RFC 9113, section 3.4).
        first.resize(24 + 9, 0);
        client.read_exact(&mut first).await?;
        let len = (usize::from(first[24]) << 16) | (usize::from(first[25]) << 8) | usize::from(first[26]);
        let at = first.len();
        first.resize(at + len, 0);
        client.read_exact(&mut first[at..]).await?;
        upstream.write_all(&first).await?;
    }
    kept.lock().unwrap().push(Kept { alpn, first });
    // Each direction's end goes on to the other, as the counter of
    // `h2_each_cli` does for its own connections.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// `podssh relay serve` with its defaults (`--http2 yes`), minting for anyone
/// and dialing the loopback: its port, the words of its events, and the CA
/// that its leaf was signed by. The idle cut is short so that a run which
/// stops carrying bytes fails in seconds rather than at the role's 180.
fn role(s: &Session, dir: &Path) -> (u16, PathBuf, PathBuf) {
    let (cert, key, ca) = role_certificate(dir);
    let (port_file, events, log) = (dir.join("role-port"), dir.join("role.events"), dir.join("role.log"));
    let mut args: Vec<String> = [
        "relay",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--mint",
        "anyone",
        "--allow-private",
        "--idle",
        "20",
        "--keepalive",
        "10",
    ]
    .map(String::from)
    .into();
    for (flag, path) in [("--cert", &cert), ("--key", &key), ("--port-file", &port_file)] {
        args.extend([flag.to_string(), path.display().to_string()]);
    }
    let child = without_proxy(s.command(&args))
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&events).unwrap())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("podssh relay serve starts");
    s.keep(child);
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return (port, events, ca);
        }
        let said = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(Instant::now() < deadline, "the role did not start within {WAIT:?}: {said}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A target on the loopback that echoes each byte, and, once it has echoed
/// `size` of them, ends its own side: the relay carries that end to the
/// session, whose output then ends and the pipe with it. An echo that stayed
/// open would leave the run waiting on it while the role counts the session
/// idle.
fn echo_then_end(size: usize) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 32 * 1024];
                let mut echoed = 0;
                loop {
                    let n = match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if std::io::Write::write_all(&mut stream, &buf[..n]).is_err() {
                        return;
                    }
                    echoed += n;
                    if echoed >= size {
                        let _ = std::net::TcpStream::shutdown(&stream, std::net::Shutdown::Write);
                        let _ = std::io::copy(&mut stream, &mut std::io::sink());
                        return;
                    }
                }
            });
        }
    });
    port
}

/// `podssh proxy` to an echo on the loopback through the edge at `edge`,
/// trusting `ca`, with `--h2-shape shape` where one is given: its run.
fn proxy(s: &Session, edge: u16, ca: &Path, shape: Option<&str>) -> Ran {
    let echo = echo_then_end(SIZE);
    let mut args: Vec<String> = vec!["proxy".into()];
    args.extend(["--relay-host".to_string(), format!("{NAME}:{edge}")]);
    args.extend(["--relay-addr".to_string(), format!("{NAME}=127.0.0.1")]);
    args.extend(["--ca-file".to_string(), ca.display().to_string()]);
    if let Some(shape) = shape {
        args.extend(["--h2-shape".to_string(), shape.to_string()]);
    }
    args.extend(["127.0.0.1".to_string(), echo.to_string()]);
    let mut cmd = without_proxy(s.command(&args));
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_TOKEN", "PODSSH_H2", "PODSSH_H2_SHAPE", "PODSSH_QUIC", "SSL_CERT_FILE"] {
        cmd.env_remove(name);
    }
    // The layer keeps its own upgrade: the contract's road is the one under
    // test (as `h2_each_cli` turns the layer off).
    cmd.env("PODSSH_RELAY_LAYER", "no").env("PODSSH_SETTINGS", "none");
    run(cmd, bytes(SIZE, 763))
}

/// The SETTINGS parameters of `frame`, a frame header and its payload, in
/// the order of the frame (RFC 9113, section 6.5).
fn settings(frame: &[u8]) -> Vec<(u16, u32)> {
    assert_eq!(frame[3], 4, "a SETTINGS frame: {frame:02x?}");
    let len = (usize::from(frame[0]) << 16) | (usize::from(frame[1]) << 8) | usize::from(frame[2]);
    let (parameters, rest) = frame[9..9 + len].as_chunks::<6>();
    assert!(rest.is_empty(), "a SETTINGS payload is whole parameters: {len} bytes");
    parameters
        .iter()
        .map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]])))
        .collect()
}

/// The parameters of `shape` that h2's client builder sends, in the order
/// that its SETTINGS frame carries them: by number (RFC 9113, section 6.5.2),
/// so id 3 is among them.
fn sent(shape: &podssh_ws::h2_road::Shape) -> Vec<(u16, u32)> {
    let mut sent: Vec<(u16, u32)> = shape.settings.iter().map(|s| (s.id, s.value)).collect();
    sent.sort_by_key(|(id, _)| *id);
    sent
}

/// A shape changes the SETTINGS of the session that the CLI opens, and the
/// session carries its bytes either way.
#[test]
fn the_shape_of_the_road_that_the_cli_opens_is_the_shape_that_was_chosen() {
    let s = Session::start("h2-shape");
    let (role_port, events, role_ca) = role(&s, &s.home);
    // A second leaf of a second CA: the edge's, which podssh trusts. The
    // role's CA is the edge's trust on its way to the role.
    let edge_dir = s.home.join("edge");
    std::fs::create_dir_all(&edge_dir).unwrap();
    let (edge_cert, edge_key, edge_ca) = role_certificate(&edge_dir);
    let edge = Edge::start(role_port, &edge_cert, &edge_key, &role_ca);
    let browser = podssh_ws::h2_road::shape_of(Some("browser")).unwrap();
    let existing = podssh_ws::h2_road::shape_of(Some("existing")).unwrap();
    for (shape, want) in [("browser", &browser), ("existing", &existing)] {
        let ran = proxy(&s, edge.port, &edge_ca, Some(shape));
        assert_eq!(ran.code, Some(0), "{shape}: {}", ran.err);
        assert_eq!(ran.out, bytes(SIZE, 763), "{shape}: each byte came back; {}", ran.err);
        let kept = edge.h2();
        let last = kept.last().unwrap_or_else(|| panic!("{shape}: no connection chose h2; {}", ran.err));
        assert_eq!(last.first[..24], *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "{shape}: HTTP/2's preface");
        assert_eq!(last.first[27], 4, "{shape}: the first frame is SETTINGS");
        assert_eq!(&last.first[28..33], &[0, 0, 0, 0, 0], "{shape}: SETTINGS, not an answer, on stream 0");
        assert_eq!(settings(&last.first[24..]), sent(want), "{shape}: the SETTINGS of the shape");
    }
    let kept = edge.h2();
    assert_eq!(
        kept.len(),
        2,
        "one connection for each run: {:?}",
        kept.iter().map(|k| k.first.len()).collect::<Vec<_>>()
    );
    assert_eq!(
        settings(&kept[0].first[24..]),
        vec![(1, 65_536), (3, 1_000), (4, 6_291_456), (6, 262_144)],
        "the browser shape's live SETTINGS, id 3 included, in the frame's order"
    );
    assert_eq!(
        settings(&kept[1].first[24..]),
        vec![(2, 0), (4, podssh_ws::h2_road::STREAM_WINDOW)],
        "the existing shape's live SETTINGS, in the frame's order"
    );
    assert_ne!(
        settings(&kept[0].first[24..]),
        settings(&kept[1].first[24..]),
        "the shape changed the session's SETTINGS"
    );
    // The role served both sessions on HTTP/2 and upgraded each path.
    let said = std::fs::read_to_string(&events).unwrap_or_default();
    assert!(said.lines().any(|l| l == "h2"), "the role served HTTP/2: {said}");
    assert_eq!(said.lines().filter(|l| *l == "upgrade").count(), 2, "the role's events: {said}");
}
