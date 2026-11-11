//! The Bare hop (T-740) against TompHTTP's own server,
//! `@tomphttp/bare-server-node` (software that podssh did not write), run by
//! `scripts/bare-hop-server.mjs` on the loopback in front of a WebSocket
//! echo of this test's: the client reaches the echo through the node, and 1
//! MiB comes back whole each way; a far port that the operator's
//! `filterRemote` refuses makes the hop fail with the node's words; and a
//! binary first message, which the specification forbids, is not an open.
//! Ignored unless `PODSSH_BARE_NODE_MODULES` names the `node_modules` where
//! the server is installed (`npm install @tomphttp/bare-server-node`).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use podssh_ws::bare;
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const LIMIT: Duration = Duration::from_secs(20);
const MIB: usize = 1 << 20;

/// The node, stopped when the test ends.
struct Node(Child, u16);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// TompHTTP's server on a free port of the loopback, refusing the far port
/// `refuse` where one is given.
fn node(refuse: Option<u16>) -> Node {
    let modules = std::env::var("PODSSH_BARE_NODE_MODULES").expect("PODSSH_BARE_NODE_MODULES");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bare-hop-server.mjs");
    let mut cmd = Command::new("node");
    cmd.arg(script).arg("0").env("NODE_PATH", modules);
    if let Some(port) = refuse {
        cmd.arg(port.to_string());
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("node runs");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).expect("the node's ready line");
    let port = line.trim().strip_prefix("ready ").and_then(|p| p.parse().ok()).expect("ready PORT");
    Node(child, port)
}

/// A WebSocket echo of each message on the loopback: its port.
async fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((head, rest)) = podssh_ws::http::request::read_request(&mut stream, Vec::new()).await else {
                    return;
                };
                let Ok(key) = podssh_ws::server::check_upgrade(&head) else { return };
                if stream.write_all(&podssh_ws::server::switching(&key)).await.is_err() {
                    return;
                }
                let session = podssh_ws::server::session(stream, rest, None);
                while let Ok(frame) = session.read_frame().await {
                    if frame.opcode != podssh_ws::frame::OPCODE_BINARY
                        || session.send_binary(&frame.payload).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn node_url(node: &Node) -> WsUrl {
    WsUrl::parse(&format!("ws://127.0.0.1:{}/bare/", node.1)).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs @tomphttp/bare-server-node: PODSSH_BARE_NODE_MODULES"]
async fn the_hop_reaches_the_far_websocket_and_one_mib_comes_back_whole() {
    let (node, far) = (node(None), echo().await);
    let far = WsUrl::parse(&format!("ws://127.0.0.1:{far}/ssh")).unwrap();
    let session = bare::dial(&node_url(&node), &far, &Trust::Default, &ProxyChoice::Direct, LIMIT, Some(LIMIT))
        .await
        .expect("the hop opens");
    let sent: Vec<u8> = (0..MIB).map(|i| (i * 7 % 251) as u8).collect();
    let mut back = Vec::with_capacity(MIB);
    for chunk in sent.chunks(16 * 1024) {
        session.send_binary(chunk).await.expect("a message goes");
        let frame = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("in time").expect("its echo");
        assert_eq!(frame.opcode, podssh_ws::frame::OPCODE_BINARY, "a binary message stays binary");
        back.extend_from_slice(&frame.payload);
    }
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "each byte came back once, in order");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs @tomphttp/bare-server-node: PODSSH_BARE_NODE_MODULES"]
async fn a_far_host_that_the_node_refuses_fails_the_hop_with_the_node_s_words() {
    let far = echo().await;
    let node = node(Some(far));
    let far = WsUrl::parse(&format!("ws://127.0.0.1:{far}/ssh")).unwrap();
    let dialed = bare::dial(&node_url(&node), &far, &Trust::Default, &ProxyChoice::Direct, LIMIT, Some(LIMIT)).await;
    let Err(failed) = dialed else { panic!("the node opened a far port that its operator refuses") };
    let why = failed.to_string();
    assert!(why.contains("through the Bare node"), "{why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs @tomphttp/bare-server-node: PODSSH_BARE_NODE_MODULES"]
async fn a_binary_first_message_is_not_a_connect_and_the_node_ends_it() {
    // The specification: a binary first message ends the connection.
    let node = node(None);
    let hop = bare::hop_url(&node_url(&node));
    let session = podssh_ws::url::dial(&hop, &Trust::Default, &ProxyChoice::Direct, LIMIT, Some(LIMIT)).await.unwrap();
    let far = WsUrl::parse("ws://127.0.0.1:9/").unwrap();
    session.send_binary(bare::connect_message(&far).as_bytes()).await.unwrap();
    let answer = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("in time");
    let opened = answer.as_ref().is_ok_and(|frame| bare::read_open(frame.opcode, &frame.payload).is_ok());
    assert!(!opened, "a binary connect opened: {answer:?}");
}
