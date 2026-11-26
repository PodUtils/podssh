//! The reverse road's own tests: its paths, its tokens, its frames and a planned stop.

use super::*;
use crate::reverse::control::{self, NodeInbound, NodeLimits};

fn head(target: &str, token: Option<&str>) -> Request {
    let header = token.map(|t| format!("X-Relay-Token: {t}\r\n")).unwrap_or_default();
    let text = format!("GET {target} HTTP/1.1\r\nHost: relay-a.test\r\n{header}\r\n");
    request::parse_request(text.as_bytes()).unwrap()
}

#[test]
fn the_paths_of_the_reverse_road_are_its_own() {
    for path in ["/v1/pair", "/v1/node/p-a", "/v1/connect/p-a", "/v1/status/p-a", "/v1/stop/p-a"] {
        assert!(serves(path), "{path}");
    }
    assert!(serves("/v1/renew/p-a"), "the role's renewal (T-592)");
    assert!(serves("/v1/rotate/p-a"), "the role's rotation of a stop token (T-615)");
    assert!(serves("/v1/halt/p-a") && serves("/v1/resume/p-a"), "the owner's halt (T-647)");
    for path in ["/v1/mint", "/v1/pairs", "/connect/h/22", "/health", "/v1/nodes/p-a"] {
        assert!(!serves(path), "{path}");
    }
}

#[test]
fn a_token_comes_from_its_header_first_then_from_the_query() {
    assert_eq!(token_of(&head("/v1/status/p-a", Some("aaaa"))).as_deref(), Some("aaaa"));
    assert_eq!(token_of(&head("/v1/status/p-a?x=1&token=bbbb", None)).as_deref(), Some("bbbb"));
    assert_eq!(token_of(&head("/v1/status/p-a?token=bbbb", Some("aaaa"))).as_deref(), Some("aaaa"));
    assert_eq!(token_of(&head("/v1/status/p-a", None)), None);
}

#[test]
fn podssh_s_node_reads_each_frame_that_the_role_sends_it() {
    let mut limits = NodeLimits::conservative();
    match control::parse_inbound(hello(true).as_bytes()).unwrap() {
        NodeInbound::Hello(hello) => {
            limits.apply(&hello);
            assert!(crate::e2e::legs::offered(&hello.extra), "the tokens of one leg (T-615)");
            assert!(crate::reverse::legs::says_rotation(&hello), "the stop token's rotation (T-615)");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(limits, NodeLimits { max_sessions: 64, max_frame_bytes: 65536 });
    match control::parse_inbound(hello(false).as_bytes()).unwrap() {
        NodeInbound::Hello(hello) => assert!(!crate::e2e::legs::offered(&hello.extra), "a carrier's offers none"),
        other => panic!("{other:?}"),
    }
    let digest = [7u8; 32];
    let told = control::parse_inbound(spent(&digest).as_bytes()).unwrap();
    assert!(matches!(&told, NodeInbound::Spent { digest: d } if *d == pairs::hex(&digest)), "{told:?}");
    let id = new_id().unwrap();
    assert!(
        matches!(control::parse_inbound(open(&id).as_bytes()).unwrap(), NodeInbound::Open { id: i } if i == id.as_str())
    );
    let closed = control::parse_inbound(close(&id, Some("relay backpressure")).as_bytes()).unwrap();
    assert!(matches!(closed, NodeInbound::Close { reason: Some(r), .. } if r == "relay backpressure"));
    assert!(matches!(
        control::parse_inbound(close(&id, None).as_bytes()).unwrap(),
        NodeInbound::Close { reason: None, .. }
    ));
    assert_ne!(new_id().unwrap(), id, "each id is drawn");
}

/// A role that mints for anyone, with no listener: its requests come on
/// pipes.
fn config() -> Arc<Config> {
    Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: super::super::tokens::Tokens::new([5; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Arc::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: None,
        events: None,
    })
}

/// T-255: while a planned stop closes each socket, a node or an operator
/// that would join gets `503` and a second to wait, not a socket that the
/// stop cuts with no Close; once it is over, the role takes them again.
#[tokio::test]
async fn while_a_planned_stop_runs_no_socket_joins() {
    use tokio::io::AsyncReadExt;
    let cfg = config();
    let made = cfg.pairs.make(super::super::tokens::now_ms()).unwrap();
    let held = cfg.pairs.hold_joins();
    let sockets =
        [(format!("/v1/node/{}", made.name), &made.node), (format!("/v1/connect/{}", made.name), &made.connect)];
    for (path, token) in sockets {
        let text = format!(
            "GET {path} HTTP/1.1\r\nHost: relay-a.test\r\nX-Relay-Token: {token}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        let head = request::parse_request(text.as_bytes()).unwrap();
        let (mut near, far) = tokio::io::duplex(4096);
        // Each wait is bounded: a socket that joined would be served on.
        let asked = request(far, head, Vec::new(), cfg.clone(), None, None);
        let _ = tokio::time::timeout(Duration::from_secs(5), asked).await;
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), near.read_to_end(&mut answer)).await;
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 503 "), "{path}: {answer}");
        assert!(answer.contains("Retry-After: 1\r\n"), "{path}: {answer}");
        assert!(answer.ends_with("reverse: relay restarting\n"), "{path}: {answer}");
    }
    drop(held);
    assert!(!cfg.pairs.stopping(), "the role takes sockets again once the stop is over");
}
