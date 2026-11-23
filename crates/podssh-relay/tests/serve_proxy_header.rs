//! The listener's rule of whom a PROXY header may name (T-807), on sockets of
//! the loopback: a balancer that the owner named must send it, and no other
//! peer may; and the brake of the role then counts each client that the
//! balancer names. The header's bytes are haproxy 2.8.30's, captured once.

#![cfg(feature = "serve")]

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::serve::brake::{monotonic, Brake, ADDRESSES, WINDOW_MS};
use podssh_relay::serve::listener::{balanced, connection, Door};
use podssh_relay::serve::proxy_header::{client_of, Trusted};
use podssh_relay::serve::slots::Slots;
use podssh_relay::serve::{self, tokens, Config, Limits, Mint};
use podssh_ws::tls_server::{acceptor_for, Served, HTTP1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// haproxy's `send-proxy` for a client at 127.0.0.2, then `HELLO`.
const HAPROXY_V1: &str =
    "50524f58592054435034203132372e302e302e32203132372e302e302e312033383236352031383430310d0a48454c4c4f";
/// Its `send-proxy-v2` for the same client, then `HELLO`.
const HAPROXY_V2: &str = "0d0a0d0a000d0a515549540a2111000c7f0000027f000001d3c947e348454c4c4f";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A connection to `listener` that sends `first`, as the listener sees it.
/// From 127.0.0.1 alone, as macOS has no other loopback address: a test
/// names the peer that `client_of` reads.
async fn connect(listener: &TcpListener, first: &[u8]) -> (TcpStream, TcpStream) {
    let socket = TcpSocket::new_v4().unwrap();
    let (client, accepted) = tokio::join!(socket.connect(listener.local_addr().unwrap()), listener.accept());
    let mut client = client.unwrap();
    client.write_all(first).await.unwrap();
    (client, accepted.unwrap().0)
}

#[tokio::test]
async fn a_trusted_balancer_must_send_the_header_and_no_other_peer_may() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trusted = Trusted::parse("127.0.0.1/32").unwrap();
    let wait = Duration::from_secs(5);
    let (balancer, stranger) = (ip("127.0.0.1"), ip("127.0.0.3"));
    // The balancer's header names the client, and the client's bytes follow.
    let (_c, mut tcp) = connect(&listener, &hex(HAPROXY_V2)).await;
    assert_eq!(client_of(&mut tcp, balancer, &trusted, wait).await, Ok(ip("127.0.0.2")));
    let mut hello = [0u8; 5];
    tcp.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"HELLO");
    // The balancer with no header: closed.
    let (_c, mut tcp) = connect(&listener, b"\x16\x03\x01\x00").await;
    assert!(client_of(&mut tcp, balancer, &trusted, wait).await.is_err());
    // Another peer that writes a header would pass for any address: closed.
    for header in [hex(HAPROXY_V1), hex(HAPROXY_V2)] {
        let (_c, mut tcp) = connect(&listener, &header).await;
        let why = client_of(&mut tcp, stranger, &trusted, wait).await.unwrap_err();
        assert!(why.contains("does not name"), "{why}");
    }
    // Another peer's TLS is its own address, its bytes left to the peeks.
    let (_c, mut tcp) = connect(&listener, b"\x16\x03\x01\x00").await;
    assert_eq!(client_of(&mut tcp, stranger, &trusted, wait).await, Ok(stranger));
    // With no flag, nothing changes: a header is the client's bytes.
    let (_c, mut tcp) = connect(&listener, &hex(HAPROXY_V1)).await;
    assert_eq!(client_of(&mut tcp, stranger, &Trusted::default(), wait).await, Ok(stranger));
    assert!(Trusted::parse("").is_err() && Trusted::parse("10.0.0.5/8").is_err());
    assert!(trusted.holds("::ffff:127.0.0.1".parse().unwrap()), "an IPv4 peer of a socket of both families");
}

/// The role behind the balancers of `trusted`, its brake one mint for each
/// address in a minute; each connection as `podssh relay serve` takes it
/// (`balanced` for a balancer's). The port, and what it said. Each client
/// is 127.0.0.1: a balancer where `trusted` holds it, else a stranger.
async fn role_behind_balancer(trusted: &str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bound.local_addr().unwrap().port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let said = events.clone();
    let say: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: tokens::Tokens::new([7; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Limits::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Brake::new(1, WINDOW_MS, ADDRESSES, monotonic()),
        usage: Default::default(),
        cover: None,
        events: Some(say),
    });
    let acceptor = acceptor_for(Served::new(None), &[HTTP1]).unwrap();
    let proxy = Arc::new(Trusted::parse(trusted).unwrap());
    let door = Door { acceptor, cleartext: true, sshd: None, published: Default::default(), proxy };
    let slots = Slots::default();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = bound.accept().await {
            match door.proxy.holds(peer.ip()) {
                true => tokio::spawn(balanced(tcp, peer.ip(), door.clone(), cfg.clone(), slots.clone())),
                false => tokio::spawn(connection(tcp, peer.ip(), door.clone(), cfg.clone())),
            };
        }
    });
    (port, events)
}

/// A mint of one session in cleartext from 127.0.0.1, after `header`: the
/// status of its answer, or none for a connection closed with no answer.
async fn mint(port: u16, header: &[u8]) -> Option<String> {
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let mut ask = header.to_vec();
    ask.extend_from_slice(b"POST /v1/mint?once=1 HTTP/1.1\r\nHost: r.test\r\nContent-Length: 2\r\n\r\n{}");
    tcp.write_all(&ask).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), tcp.read_to_end(&mut answer)).await.expect("an end in time");
    let text = String::from_utf8_lossy(&answer);
    text.starts_with("HTTP/1.1 ").then(|| text.split(' ').nth(1).unwrap_or_default().to_string())
}

/// A header of version 1 for a client at `client`.
fn v1(client: &str) -> Vec<u8> {
    format!("PROXY TCP4 {client} 127.0.0.1 40000 443\r\n").into_bytes()
}

#[tokio::test]
async fn the_brake_counts_the_client_that_the_balancer_names() {
    let (port, _) = role_behind_balancer("127.0.0.1").await;
    assert_eq!(mint(port, &v1("192.0.2.1")).await.as_deref(), Some("200"));
    assert_eq!(mint(port, &v1("192.0.2.1")).await.as_deref(), Some("429"), "the client's second");
    // haproxy's own header names 127.0.0.2, a client apart.
    assert_eq!(mint(port, &hex(HAPROXY_V2)[..28]).await.as_deref(), Some("200"));
    assert_eq!(mint(port, &v1("192.0.2.2")).await.as_deref(), Some("200"), "another client");
    // The balancer with no header: closed.
    assert_eq!(mint(port, b"").await, None);
    // A role whose balancer is elsewhere: 127.0.0.1 is a stranger, closed
    // with a header, and itself with none.
    let (port, events) = role_behind_balancer("192.0.2.1").await;
    assert_eq!(mint(port, &v1("192.0.2.9")).await, None);
    assert_eq!(mint(port, b"").await.as_deref(), Some("200"));
    let said = events.lock().unwrap().join("\n");
    assert!(said.contains("which --proxy-protocol does not name"), "{said}");
}
