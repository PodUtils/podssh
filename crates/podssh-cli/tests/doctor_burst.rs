//! `podssh doctor`'s burst (T-747), as a process, against relay hosts of the
//! loopback with TLS of the test's own CA: a clean one; one that resets each
//! connection past N open at once; one that resets each; one that takes each
//! connection and never answers. `--json` carries the counts of each round.
//! `--jobs 1` and the default give one verdict. No byte leaves the loopback.

mod cleanup;

#[path = "update_support/mod.rs"]
mod update_support;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const LIMIT: Duration = Duration::from_secs(120);

/// The variables that would steer doctor away from the test's relay.
const STEERING: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "PODSSH_OFFLINE",
    "PODSSH_RELAY",
    "PODSSH_RELAY_ADDR",
    "PODSSH_RELAY_TOKEN",
    "PODSSH_FORWARDER",
    "PODSSH_VIA",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

/// What the relay of a test does with each connection.
#[derive(Clone, Copy, Debug)]
enum Relay {
    Clean,
    /// Resets each connection past this many open at once.
    Limit(usize),
    ResetsEach,
    Silent,
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-doctor-burst-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A reset: the connection closed with no linger, as a gateway's RST, after
/// the client's first bytes, as a gateway resets once it read the hello. A
/// reset before them races the client's write: macOS then answers that
/// write with EPIPE, a close, where Linux says reset; after them, the
/// client's read meets the RST on each system.
fn reset(tcp: tokio::net::TcpStream) {
    tokio::spawn(async move {
        let mut tcp = tcp;
        let mut hello = [0u8; 4096];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read(&mut hello)).await;
        let _ = tcp.set_zero_linger();
        drop(tcp);
    });
}

/// The relay on the runtime `runtime`: its port.
fn serve(runtime: &tokio::runtime::Runtime, home: &std::path::Path, relay: Relay) -> (u16, PathBuf) {
    let (acceptor, ca) = update_support::acceptor(home, &["127.0.0.1"]);
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    let open = Arc::new(AtomicUsize::new(0));
    runtime.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, open) = (acceptor.clone(), open.clone());
            match relay {
                Relay::ResetsEach => reset(tcp),
                Relay::Limit(n) if open.load(Ordering::SeqCst) >= n => reset(tcp),
                Relay::Silent => {
                    tokio::spawn(async move {
                        let mut tcp = tcp;
                        let mut sink = [0u8; 4096];
                        while tcp.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                    });
                }
                Relay::Clean | Relay::Limit(_) => {
                    open.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        if let Ok(mut tls) = acceptor.accept(tcp).await {
                            // A request (the relay's own checks) is refused at
                            // once, as a relay refuses; a handshake alone (the
                            // burst's) ends with its end.
                            let mut sink = [0u8; 4096];
                            if tls.read(&mut sink).await.is_ok_and(|n| n > 0) {
                                let refusal =
                                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = tls.write_all(refusal).await;
                                let _ = tls.shutdown().await;
                            }
                        }
                        open.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            }
        }
    });
    (port, ca)
}

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `doctor --quick --json` against `relay`, with `extra`: the line
/// `concurrency`, and how long the run took.
fn burst(tag: &str, relay: Relay, extra: &[&str]) -> (serde_json::Value, Duration) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch(tag);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, ca) = serve(&runtime, &home, relay);
    let relay_host = format!("127.0.0.1:{port}");
    let ca = ca.display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["doctor", "--quick", "--json", "--relay-host", &relay_host, "--ca-file", &ca]).args(extra);
    cmd.env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_CACHE_DIR", home.join("cache")).env("PODSSH_SETTINGS", "none").env("PODSSH_STUN", "no");
    let began = Instant::now();
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || std::io::read_to_string(&mut stdout).unwrap_or_default());
    while child.try_wait().unwrap().is_none() {
        if began.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("doctor still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = out.join().unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("one JSON object: {out}"));
    let line = doc["checks"].as_array().unwrap().iter().find(|c| c["check"] == "concurrency").cloned();
    drop(runtime);
    (line.unwrap_or_else(|| panic!("no line concurrency: {out}")), began.elapsed())
}

fn detail(line: &serde_json::Value) -> &str {
    line["detail"].as_str().unwrap()
}

#[test]
fn a_clean_relay_shows_no_limit_with_six_of_six_in_each_round() {
    let (line, _) = burst("clean", Relay::Clean, &[]);
    assert_eq!(line["status"], "ok", "{line}");
    assert!(detail(&line).contains("no concurrency limit seen up to 6"), "{line}");
    let numbers = &line["samples"];
    assert_eq!(
        (numbers["k"].as_u64(), numbers["burst_ok"].as_u64(), numbers["control_ok"].as_u64()),
        (Some(6), Some(6), Some(6))
    );
}

#[test]
fn a_relay_that_resets_past_three_open_is_a_limit_of_three_with_jobs_1_or_not() {
    for extra in [&[][..], &["--jobs", "1"][..]] {
        let (line, _) = burst("limit", Relay::Limit(3), extra);
        assert_eq!(line["status"], "FAIL", "{extra:?}: {line}");
        assert!(
            detail(&line).contains("concurrency limit: 3/6 handshakes succeed together, 6/6 one at a time"),
            "{line}"
        );
        assert!(detail(&line).contains("reset"), "{line}");
        assert_eq!((line["samples"]["burst_ok"].as_u64(), line["samples"]["control_ok"].as_u64()), (Some(3), Some(6)));
    }
}

/// GitHub #99's case: each handshake fails alone too, so no limit is shown.
#[test]
fn a_relay_that_resets_each_is_not_shown_to_be_a_limit() {
    let (line, _) = burst("resets", Relay::ResetsEach, &[]);
    assert_eq!(line["status"], "unknown", "{line}");
    assert!(detail(&line).contains("not shown to be a concurrency limit: 6/6 handshakes fail even alone"), "{line}");
    assert_eq!(line["samples"]["control_ok"].as_u64(), Some(0));
}

#[test]
fn a_silent_relay_times_out_within_the_budget() {
    let (line, _) = burst("silent", Relay::Silent, &[]);
    assert!(detail(&line).contains("timeout") && !detail(&line).contains("reset"), "{line}");
    assert!(detail(&line).contains("cut at 10 s"), "{line}");
    let bursts = line["samples"]["bursts"].as_array().unwrap();
    assert_eq!(bursts[0]["failed"]["timeout"].as_u64(), Some(6), "{line}");
}
