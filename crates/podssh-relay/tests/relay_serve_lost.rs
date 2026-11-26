//! A node's socket that resets on the loopback, its TCP closed with RST as a
//! host that went away closes it: podssh's relay role lets the socket go at
//! once, so the node's next socket is taken with no `409` and an operator
//! reaches the node on it (PodUtils/podnet#604). The pipes of the role's own
//! tests (`serve::reverse::lost`) cover a failed write and a silent link.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::time::Duration;

use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::session::RelaySession;
use role_harness::{next, next_text, Role, LIMIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A node's socket on a raw TCP connection, which the test can reset: the
/// upgrade written by hand, as a client of the contract that podssh did not
/// shape writes it.
async fn raw_node(role: &Role, path: &str, token: &str) -> RelaySession<TcpStream> {
    let mut tcp = TcpStream::connect(("127.0.0.1", role.relay.port)).await.unwrap();
    let upgrade = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Relay-Token: {token}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(upgrade.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = tokio::time::timeout(LIMIT, tcp.read(&mut chunk)).await.expect("an answer in time").unwrap();
        assert!(n > 0, "the role ended with no answer");
        got.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&got[..end]).into_owned();
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    // An RST at the drop, not a FIN.
    tcp.set_zero_linger().unwrap();
    RelaySession::new(tcp, got[end..].to_vec(), None, LIMIT)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_whose_tcp_reset_is_taken_again_at_once_and_reached() {
    let role = Role::start().await;
    let pair = role.pair();
    let path = format!("/v1/node/{}", pair.name);
    let first = raw_node(&role, &path, pair.node_token()).await;
    assert_eq!(next_text(&first).await["type"], "hello");
    drop(first);

    // Far under the five seconds of a Close that the role would wait for,
    // and the node's minute of `409` before it gives the route up.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !role.said("reverse node gone") && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let node = match role.socket(&path, pair.node_token()).await {
        Ok(node) => node,
        Err(e) => panic!("the node's next socket after a reset: {e}; the role said {:?}", role.events.lock().unwrap()),
    };
    assert_eq!(next_text(&node).await["type"], "hello");
    // Its line names the node's client and the pair (T-1035).
    let said = role.events.lock().unwrap().clone();
    let lost: Vec<&String> = said.iter().filter(|l| l.starts_with("reverse node lost: ")).collect();
    assert!(!lost.is_empty(), "{said:?}");
    for line in lost {
        assert_eq!(podssh_relay::serve::said::field(line, "client"), Some("127.0.0.1"), "{line}");
        assert_eq!(podssh_relay::serve::said::field(line, "pair"), Some(pair.name.as_str()), "{line}");
    }

    let operator =
        role.socket(&format!("/v1/connect/{}", pair.name), pair.connect_token()).await.expect("the operator's socket");
    let open = next_text(&node).await;
    assert_eq!(open["type"], "open", "{open}");
    let id = open["id"].as_str().expect("an id").to_string();
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    node.send_binary(&[id.as_bytes(), b"SSH-2.0-node\r\n"].concat()).await.unwrap();
    let ready = next_text(&operator).await;
    assert_eq!((ready["type"].as_str(), ready["id"].as_str()), (Some("ready"), Some(id.as_str())));
    assert_eq!(next(&operator).await, Some((OPCODE_BINARY, b"SSH-2.0-node\r\n".to_vec())));
}
