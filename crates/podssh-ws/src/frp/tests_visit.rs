//! The visitor's side of the frp road (T-498): the names that frpc gives
//! the services on frps, a visitor's login as its user for frps's
//! `allowUsers`, the visit with that login's run id, the login held by
//! frp's heartbeat, and the upgrade to frps's WebSocket. The test plays
//! frps's side of yamux by hand, as `super::tests` does.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use zeroize::Zeroizing;

use super::cfb::{self, Cfb};
use super::control::Session;
use super::dial::{self, Server};
use super::msg::{self, Msg};
use super::mux::Mux;
use super::mux_frame as frame;
use super::node::{self, Road};
use super::tests::read_frame;
use super::FrpError;
use crate::tls::Trust;

const TOKEN: &str = "token-of-the-visit-test";
const SECRET: &str = "secret-of-the-visit-test";
const LIMIT: Duration = Duration::from_secs(5);

fn road(user: &str, owner: &str) -> Road {
    Road {
        server: Server::Tls { host: "frps.example".into(), port: 7000 },
        token: Arc::new(Zeroizing::new(TOKEN.into())),
        secret: Arc::new(Zeroizing::new(SECRET.into())),
        trust: Trust::Default,
        user: user.into(),
        owner: owner.into(),
    }
}

/// The next message that the client sends on the stream `id`, in clear, as
/// frps reads it; window updates and the frames of other streams are passed
/// over.
async fn message_on(io: &mut DuplexStream, id: u32) -> Msg {
    let mut got = Vec::new();
    loop {
        let (h, payload) = tokio::time::timeout(LIMIT, read_frame(io)).await.expect("a frame in time");
        if h.kind == frame::DATA && h.stream == id {
            got.extend_from_slice(&payload);
            if let Some((m, _)) = msg::decode(&got).unwrap() {
                return m;
            }
        }
    }
}

/// frps's answer on the stream `id`, in clear.
async fn answer(io: &mut DuplexStream, id: u32, kind: u8, body: Value) {
    io.write_all(&frame::data(id, frame::ACK, &msg::encode(kind, &body))).await.unwrap();
}

#[test]
fn the_names_on_frps_are_frpc_s_user_dot_name() {
    assert_eq!(road("", "").registered("lab"), "lab");
    assert_eq!(road("", "").visited("lab"), "lab");
    assert_eq!(road("alice", "").registered("lab"), "alice.lab", "frpc's proxy of a user");
    assert_eq!(road("alice", "").visited("lab"), "alice.lab", "a node and a visitor of one file meet");
    assert_eq!(road("guest", "lab").visited("sshd"), "lab.sshd", "frpc's serverUser");
    assert_eq!(road("", "lab").visited("sshd"), "lab.sshd");
}

#[test]
fn a_visitor_s_login_names_its_user_and_asks_for_no_work_connection() {
    let login = msg::visitor_login(TOKEN, "guest", 1_700_000_000);
    assert_eq!(login["user"], "guest");
    assert_eq!(login["pool_count"], 0);
    assert_eq!(login["privilege_key"], msg::auth_key(TOKEN, 1_700_000_000));
    assert!(!login.to_string().contains(TOKEN), "{login}");
    assert_eq!(msg::login(TOKEN, "", "", 1)["pool_count"], 1, "a node's login keeps its pool");
}

#[tokio::test]
async fn a_visitor_with_a_user_logs_in_then_visits_with_its_run_id_and_carries_bytes() {
    let (ours, mut frps) = tokio::io::duplex(1 << 20);
    let mux = Mux::client(ours);
    let visiting = tokio::spawn(async move {
        let road = road("guest", "lab");
        node::visit_on(mux, &road, "sshd").await
    });
    let login = message_on(&mut frps, 1).await;
    assert_eq!(login.kind, msg::LOGIN);
    assert_eq!((login.text("user"), login.body["pool_count"].as_i64()), ("guest", Some(0)));
    let ts = login.body["timestamp"].as_i64().unwrap();
    assert_eq!(login.text("privilege_key"), msg::auth_key(TOKEN, ts));
    answer(&mut frps, 1, msg::LOGIN_RESP, json!({ "version": "0.71.1", "run_id": "run-7", "error": "" })).await;

    let ask = message_on(&mut frps, 3).await;
    assert_eq!(ask.kind, msg::NEW_VISITOR_CONN, "the visit on a stream of its own");
    assert_eq!((ask.text("proxy_name"), ask.text("run_id")), ("lab.sshd", "run-7"));
    let ts = ask.body["timestamp"].as_i64().unwrap();
    assert_eq!(ask.text("sign_key"), msg::auth_key(SECRET, ts));
    answer(&mut frps, 3, msg::NEW_VISITOR_CONN_RESP, json!({ "proxy_name": "lab.sshd", "error": "" })).await;
    let mut stream = tokio::time::timeout(LIMIT, visiting).await.unwrap().unwrap().expect("the visit");

    // The service's bytes, each way, in clear on the visit's stream.
    frps.write_all(&frame::data(3, 0, b"SSH-2.0-sshd\r\n")).await.unwrap();
    let mut banner = [0u8; 14];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-2.0-sshd\r\n");
    stream.write_all(b"SSH-2.0-podssh\r\n").await.unwrap();
    let mut up = Vec::new();
    while up.len() < 16 {
        let (h, payload) = tokio::time::timeout(LIMIT, read_frame(&mut frps)).await.unwrap();
        if h.kind == frame::DATA && h.stream == 3 {
            up.extend_from_slice(&payload);
        }
    }
    assert_eq!(up, b"SSH-2.0-podssh\r\n");
}

#[tokio::test]
async fn a_visitor_with_no_user_visits_with_no_login_and_says_frps_s_refusal() {
    let (ours, mut frps) = tokio::io::duplex(1 << 20);
    let mux = Mux::client(ours);
    let visiting = tokio::spawn(async move {
        let road = road("", "");
        node::visit_on(mux, &road, "lab").await
    });
    let ask = message_on(&mut frps, 1).await;
    assert_eq!(ask.kind, msg::NEW_VISITOR_CONN, "the first stream is the visit: no login");
    assert_eq!((ask.text("proxy_name"), ask.text("run_id")), ("lab", ""));
    let words = "visitor connection of [lab] auth failed";
    answer(&mut frps, 1, msg::NEW_VISITOR_CONN_RESP, json!({ "proxy_name": "lab", "error": words })).await;
    let refused = tokio::time::timeout(LIMIT, visiting).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(&refused, FrpError::Refused { step: "the visit", words: w } if w == words), "{refused}");
}

#[tokio::test]
async fn a_visitor_s_login_that_frps_refuses_ends_the_visit_in_its_words() {
    let (ours, mut frps) = tokio::io::duplex(1 << 20);
    let mux = Mux::client(ours);
    let visiting = tokio::spawn(async move {
        let road = road("stranger", "lab");
        node::visit_on(mux, &road, "sshd").await
    });
    let _login = message_on(&mut frps, 1).await;
    let words = "token in login doesn't match token from configuration";
    answer(&mut frps, 1, msg::LOGIN_RESP, json!({ "version": "0.71.1", "error": words })).await;
    let refused = tokio::time::timeout(LIMIT, visiting).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(&refused, FrpError::Refused { step: "the login", .. }), "{refused}");
    assert!(refused.is_bad_token(), "{refused}");
}

#[tokio::test]
async fn a_held_login_sends_frp_s_heartbeat_in_the_control_stream_s_cipher() {
    let (ours, mut frps) = tokio::io::duplex(1 << 20);
    let mux = Mux::client(ours);
    let login = tokio::spawn(async move { Session::login_visitor(mux, TOKEN, "guest").await });
    let _ = message_on(&mut frps, 1).await;
    answer(&mut frps, 1, msg::LOGIN_RESP, json!({ "version": "0.71.1", "run_id": "run-1", "error": "" })).await;
    let session = tokio::time::timeout(LIMIT, login).await.unwrap().unwrap().expect("the login");
    let held = tokio::spawn(session.keep(Duration::from_millis(50)));
    // The client's IV, then a ping in AES-128-CFB of the token's key.
    let key = cfb::key(TOKEN.as_bytes());
    let mut sealed = Vec::new();
    let ping = loop {
        let (h, payload) = tokio::time::timeout(LIMIT, read_frame(&mut frps)).await.expect("a heartbeat in time");
        if h.kind == frame::DATA && h.stream == 1 {
            sealed.extend_from_slice(&payload);
        }
        if sealed.len() > cfb::BLOCK + 9 {
            let iv: [u8; cfb::BLOCK] = sealed[..cfb::BLOCK].try_into().unwrap();
            let mut clear = sealed[cfb::BLOCK..].to_vec();
            Cfb::decrypter(&key, &iv).apply(&mut clear);
            if let Some((m, _)) = msg::decode(&clear).unwrap() {
                break m;
            }
        }
    };
    assert_eq!(ping.kind, msg::PING);
    let ts = ping.body["timestamp"].as_i64().unwrap();
    assert_eq!(ping.text("privilege_key"), msg::auth_key(TOKEN, ts));
    held.abort();
}

#[test]
fn the_upgrade_to_frps_s_websocket_names_an_origin_as_frpc_does() {
    let Server::WebSocket(url) = Server::parse("wss://edge.example:8443").unwrap() else { panic!("a WebSocket") };
    let text = String::from_utf8(dial::upgrade_request(&url, "dGhlIHNhbXBsZSBub25jZQ==").unwrap()).unwrap();
    assert!(text.starts_with("GET /~!frp HTTP/1.1\r\n"), "{text}");
    assert!(text.contains("\r\nOrigin: http://edge.example:8443\r\n"), "{text}");
    assert!(text.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\n") && !text.ends_with("\r\n\r\n\r\n"), "one empty line at the end: {text}");
}
