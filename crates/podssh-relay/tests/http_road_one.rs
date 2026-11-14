//! The HTTP road's one-POST form (T-622) at podssh's relay role on the
//! loopback, with curl as its client, software that podssh did not write:
//! one POST whose body in chunks is the way up and whose answer, after the
//! role's mark, is the way down. Straight to the role and through a stand-in
//! of a hop that passes bodies as they come, 20 MiB go each way to an echo
//! with equal digests, on one connection. A client that writes its chunks
//! by hand, one and then a pause, gets the mark and the echo of that chunk
//! while its body is open, through the hop that streams; through the
//! stand-in that holds a body to its end, nothing comes while the body is
//! open, which is what the client's bound on the mark reads. The open's checks hold: a
//! missing token, and a body that is not in chunks, are refused.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test http_road_one
#![cfg(all(feature = "serve", feature = "plain-ws", unix))]

mod http_road_harness;
mod role_harness;

use std::process::Stdio;
use std::time::Duration;

use http_road_harness::{bytes, each_way, echo_target, open, raw, road, Faults, Proxy, MIB};
use podssh_relay::http_road::client::End;
use podssh_relay::http_road::Form;
use podssh_relay::serve::http_road::one::MARK;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use role_harness::Role;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// The role, which dials the loopback, and a token of its own.
async fn role() -> (Role, String) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// A scratch directory of the test's own, gone when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-one-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// curl's POST of the form to the loopback's `port`, to the echo at
/// `target`: its body from curl's stdin in chunks, its answer to stdout. The
/// token goes in a file of headers, not in curl's arguments.
fn curl(scratch: &Scratch, port: u16, target: u16, token: &str) -> tokio::process::Child {
    let headers = scratch.0.join("headers");
    std::fs::write(&headers, format!("X-Relay-Token: {token}\nTransfer-Encoding: chunked\n")).unwrap();
    Command::new("curl")
        .args(["-sS", "-N", "--http1.1", "--no-buffer", "-X", "POST", "-T", "-", "-H"])
        .arg(format!("@{}", headers.display()))
        .arg(format!("http://127.0.0.1:{port}/v1/http/one/127.0.0.1/{target}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("curl")
}

/// `size` bytes up through curl at `port`, at once with the answer read:
/// the answer's mark, and the digest of what came after it.
async fn curl_each_way(port: u16, target: u16, token: &str, size: usize) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let scratch = Scratch::new(&format!("{port}"));
    let mut child = curl(&scratch, port, target, token);
    let sent = bytes(size, 7);
    let want: [u8; 32] = Sha256::digest(&sent).into();
    let mut stdin = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        stdin.write_all(&sent).await.unwrap();
        drop(stdin);
    });
    let mut stdout = child.stdout.take().unwrap();
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(120), stdout.read_to_end(&mut got)).await;
    read.expect("the answer's end in time").unwrap();
    writer.await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await.expect("curl's end").unwrap();
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err).await;
    assert!(status.success(), "curl: {status}: {err}");
    let mark = got[..MARK.len().min(got.len())].to_vec();
    let after: [u8; 32] = Sha256::digest(&got[mark.len()..]).into();
    (mark, after, want)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curl_carries_20_mib_each_way_in_one_post_straight_to_the_role() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let (mark, got, want) = curl_each_way(role.relay.port, target, &token, 20 * MIB).await;
    assert_eq!(mark, MARK);
    assert_eq!(got, want, "the echo's digest is the body's");
    assert!(
        role.said("http one open") && role.said("http one close: the target ended"),
        "{:?}",
        role.events.lock().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curl_carries_20_mib_each_way_through_a_hop_that_passes_bodies_as_they_come() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let proxy = Proxy::start(role.relay.port, Faults { stream_bodies: true, ..Faults::default() }).await;
    let (mark, got, want) = curl_each_way(proxy.port, target, &token, 20 * MIB).await;
    assert_eq!(mark, MARK);
    assert_eq!(got, want);
    assert_eq!(proxy.count(|c| &c.requests), 1, "one request carried the session");
}

/// The mark comes at once where the hop streams, and not while the body is
/// open where the hop holds it: the client's bound on the mark tells them
/// apart. curl holds what it reads of its stdin until a buffer fills, so
/// this test writes the request's chunks itself, one and then a pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mark_comes_at_once_unless_a_hop_holds_the_body() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    for (faults, comes) in [(Faults { stream_bodies: true, ..Faults::default() }, true), (Faults::default(), false)] {
        let proxy = Proxy::start(role.relay.port, faults).await;
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let head = format!(
            "POST /v1/http/one/127.0.0.1/{target} HTTP/1.1\r\nHost: r\r\nX-Relay-Token: {token}\r\n\
             Transfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n"
        );
        tcp.write_all(head.as_bytes()).await.unwrap();
        let (mut from, mut to) = tcp.into_split();
        let mut early = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        // Within 2 s: where the hop streams, the answer's head, the mark and
        // the echo of the open body's first chunk; else nothing.
        while !early.ends_with(b"5\r\nfirst\r\n") {
            let mut buf = [0u8; 4096];
            match tokio::time::timeout_at(deadline, from.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => early.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&early).into_owned();
        if comes {
            assert!(text.starts_with("HTTP/1.1 200 "), "{text}");
            let mark = format!("{:x}\r\n{}\r\n", MARK.len(), String::from_utf8_lossy(MARK));
            assert!(
                text.ends_with(&format!("{mark}5\r\nfirst\r\n")),
                "the mark, then the echo while the body is open: {text:?}"
            );
        } else {
            assert!(early.is_empty(), "nothing while a hop holds the body: {text:?}");
        }
        // The body's end lets the holding hop send the request on: the
        // session then ends whole, its mark first, and the last chunk.
        to.write_all(b"0\r\n\r\n").await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), from.read_to_end(&mut rest)).await.unwrap().unwrap();
        let whole = String::from_utf8_lossy(&[early, rest].concat()).into_owned();
        let body = whole.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        assert_eq!(
            body,
            format!("{:x}\r\n{}\r\n5\r\nfirst\r\n0\r\n\r\n", MARK.len(), String::from_utf8_lossy(MARK)),
            "{faults:?}"
        );
    }
}

#[tokio::test]
async fn the_form_takes_the_token_and_a_body_in_chunks() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let path = format!("/v1/http/one/127.0.0.1/{target}");
    let (status, text) = raw(
        role.relay.port,
        &format!("POST {path} HTTP/1.1\r\nHost: r\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("missing or wrong token"), "{text}");
    let (status, text) = raw(
        role.relay.port,
        &format!("POST {path} HTTP/1.1\r\nHost: r\r\nX-Relay-Token: {token}\r\nContent-Length: 2\r\n\r\nhi"),
    )
    .await;
    assert_eq!(status, 411, "{text}");
    assert!(!role.said("http one open"));
}

/// The end of a session whose target ended after the client's last byte.
fn target_closed() -> Option<End> {
    Some(End::Closed { code: 1000, reason: "target closed".into() })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn podssh_s_client_opens_the_one_post_form_first_and_carries_20_mib_each_way() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let opened = open(&road(role.relay.port, "127.0.0.1"), target, &token, None).await;
    assert_eq!(opened.form, Form::One, "the form first where the host is not known to refuse it");
    let ended = each_way(opened, b"", 20 * MIB, 5).await;
    assert!(ended.is_none() || ended == target_closed(), "{ended:?}");
    assert!(role.said("http one open"), "{:?}", role.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn behind_a_hop_that_holds_the_body_the_client_takes_the_split_form_and_keeps_it_for_the_run() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let proxy = Proxy::start(role.relay.port, Faults::default()).await;
    let road = road(proxy.port, "127.0.0.1");
    let started = std::time::Instant::now();
    let opened = open(&road, target, &token, None).await;
    let first = started.elapsed();
    assert_eq!(opened.form, Form::Split, "the mark did not come: the split form");
    assert!(first < Duration::from_secs(15), "within the mark's bound and the split's open: {first:?}");
    assert_eq!(each_way(opened, b"", 2 * MIB, 6).await, target_closed());
    // The same road in the same run: the way that held the form is known.
    let started = std::time::Instant::now();
    let opened = open(&road, target, &token, None).await;
    assert_eq!(opened.form, Form::Split);
    assert!(started.elapsed() < first, "no second wait for the mark: {:?} after {first:?}", started.elapsed());
}
