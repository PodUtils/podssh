//! The role's side of the invariants 6 to 10 of the HTTP road (T-319,
//! GitHub #221), request by request, as `pod-relay`'s client reads them:
//! pod-relay's own tests drive the client against a stand-in, so these drive
//! podssh's server. A batch sent again gets the same `X-Seq` and reaches the
//! target once; a full window answers `503` with `X-Refuse: full` and does
//! not move; a last batch with no `total=`, or with one that differs from
//! the bytes stored, is refused or fails the session `1002`; a clean end
//! names the bytes down in `X-Total`; an exchange names its batch; each
//! refusal of the role names its reason.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test http_road_role
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod http_road_harness;
mod role_harness;

use http_road_harness::{echo_target, raw};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use role_harness::Role;

/// The role, which dials the loopback, and a token of its own.
async fn role() -> (Role, String) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// One request, whole, on a connection of its own.
fn ask(method: &str, path: &str, headers: &str, body: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A session of the role to the loopback's `target`: its id, and the header
/// of its key.
async fn session(role: &Role, token: &str, target: u16) -> (String, String) {
    let open = ask("POST", &format!("/v1/http/open/127.0.0.1/{target}"), &format!("X-Relay-Token: {token}\r\n"), "");
    let (status, text) = raw(role.relay.port, &open).await;
    assert_eq!(status, 200, "{text}");
    let doc: serde_json::Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    let (id, key) = (doc["session"].as_str().unwrap(), doc["key"].as_str().unwrap());
    (id.to_string(), format!("X-Session-Key: {key}\r\n"))
}

/// A header's value in an answer's text.
fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let head = text.split_once("\r\n\r\n").map_or(text, |(head, _)| head);
    head.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The body of an answer's text.
fn body(text: &str) -> &str {
    text.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_sent_again_gets_the_same_seq_and_reaches_the_target_once_and_a_clean_end_names_its_total() {
    let (role, token) = role().await;
    let target = echo_target(b"hi\n").await;
    let (id, key) = session(&role, &token, target).await;
    let up = |query: &str, bytes: &str| ask("POST", &format!("/v1/http/s/{id}/up?{query}"), &key, bytes);
    // The same batch again, before and after the next: the same answer.
    let batches = [("seq=0", "abc", "0"), ("seq=0", "abc", "0"), ("seq=1", "de", "1"), ("seq=0", "abc", "0")];
    for (query, bytes, seq) in batches {
        let (status, text) = raw(role.relay.port, &up(query, bytes)).await;
        assert_eq!((status, header(&text, "X-Seq")), (204, Some(seq)), "{query}: {text}");
    }
    let (status, text) = raw(role.relay.port, &up("seq=2&fin=1", "")).await;
    assert_eq!(status, 400, "a last batch with no total: {text}");
    let (status, text) = raw(role.relay.port, &up("seq=2&fin=1&total=5", "")).await;
    assert_eq!((status, header(&text, "X-Seq")), (204, Some("2")), "{text}");
    let (status, text) = raw(role.relay.port, &up("seq=3", "f")).await;
    assert_eq!(status, 409, "no batch after the last: {text}");
    // The echo's bytes down, each once: the greeting, then each batch once.
    let mut came = String::new();
    while came.len() < 8 {
        let down = ask("GET", &format!("/v1/http/s/{id}/down?at={}&wait=5000", came.len()), &key, "");
        let (status, text) = raw(role.relay.port, &down).await;
        assert_eq!(status, 200, "{came:?}: {text}");
        came.push_str(body(&text));
    }
    assert_eq!(came, "hi\nabcde");
    let down = ask("GET", &format!("/v1/http/s/{id}/down?at=8&wait=5000"), &key, "");
    let (status, text) = raw(role.relay.port, &down).await;
    assert_eq!(status, 410, "{text}");
    assert_eq!(header(&text, "X-Close"), Some("1000 target closed"), "{text}");
    assert_eq!(header(&text, "X-Total"), Some("8"), "the bytes down of the whole session: {text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_window_refuses_full_and_does_not_move() {
    let (role, token) = role().await;
    // A target that takes the connection and reads nothing: once the
    // socket's buffers are full, the role's window fills.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().port();
    let held = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        drop(tcp);
    });
    let (id, key) = session(&role, &token, target).await;
    let batch = "a".repeat(256 * 1024);
    let up = |seq: u64| ask("POST", &format!("/v1/http/s/{id}/up?seq={seq}"), &key, &batch);
    let mut full = None;
    for seq in 0..200u64 {
        let (status, text) = raw(role.relay.port, &up(seq)).await;
        if status == 503 {
            full = Some((seq, text));
            break;
        }
        assert_eq!((status, header(&text, "X-Seq")), (204, Some(seq.to_string().as_str())), "{text}");
    }
    let (seq, text) = full.expect("the window filled within 50 MiB");
    assert_eq!(header(&text, "X-Refuse"), Some("full"), "{text}");
    assert_eq!(header(&text, "Retry-After"), Some("1"), "{text}");
    // The window did not move: the next number is still the refused one,
    // and a batch stored before is acknowledged again, at once.
    let (status, text) = raw(role.relay.port, &up(seq + 1)).await;
    assert_eq!(status, 409, "{text}");
    assert!(body(&text).contains(&format!("where the next is {seq}")), "{text}");
    let (status, text) = raw(role.relay.port, &up(seq - 1)).await;
    assert_eq!((status, header(&text, "X-Seq")), (204, Some((seq - 1).to_string().as_str())), "{text}");
    held.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_total_that_differs_from_the_bytes_stored_fails_the_session() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let (id, key) = session(&role, &token, target).await;
    let up = |query: &str, bytes: &str| ask("POST", &format!("/v1/http/s/{id}/up?{query}"), &key, bytes);
    let (status, text) = raw(role.relay.port, &up("seq=0", "abc")).await;
    assert_eq!((status, header(&text, "X-Seq")), (204, Some("0")), "{text}");
    let (status, text) = raw(role.relay.port, &up("seq=1&fin=1&total=9", "de")).await;
    assert_eq!(status, 410, "{text}");
    let close = header(&text, "X-Close").unwrap_or_default();
    assert!(close.starts_with("1002 count mismatch"), "{text}");
    assert_eq!(header(&text, "X-Total"), None, "no count of a clean end: {text}");
    assert!(role.said("http close 1002"), "{:?}", role.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exchange_names_its_batch_and_each_refusal_its_reason() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let (id, key) = session(&role, &token, target).await;
    let x = ask("POST", &format!("/v1/http/s/{id}/x?seq=0&at=0&wait=0"), &key, "hi");
    for _ in 0..2 {
        let (status, text) = raw(role.relay.port, &x).await;
        assert!(matches!(status, 200 | 204), "{text}");
        assert_eq!(header(&text, "X-Seq"), Some("0"), "{text}");
    }
    let unknown = ask("GET", &format!("/v1/http/s/{}/down?at=0", "0".repeat(32)), &key, "");
    let (status, text) = raw(role.relay.port, &unknown).await;
    assert_eq!((status, header(&text, "X-Refuse")), (404, Some("unknown session")), "{text}");
    let (status, text) = raw(role.relay.port, &ask("POST", &format!("/v1/http/open/127.0.0.1/{target}"), "", "")).await;
    assert_eq!((status, header(&text, "X-Refuse")), (403, Some("not allowed")), "{text}");
    let minted = format!("X-Relay-Token: {token}\r\n");
    let (status, text) = raw(role.relay.port, &ask("POST", "/v1/http/open/127.0.0.1/25", &minted, "")).await;
    assert_eq!((status, header(&text, "X-Refuse")), (403, Some("not allowed")), "the policy's refusal: {text}");
}
