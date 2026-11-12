//! The TURN road (T-621) against a stand-in TURN server on the loopback that
//! answers as RFC 8656 and RFC 6062 lay out, with the credential checked by
//! MESSAGE-INTEGRITY: the bytes on a second connection, a Refresh before the
//! lifetime ends, a server with no TCP allocation (442) and a wrong password
//! refused. coturn itself runs in `crates/podssh-cli/tests/turn_road.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::stun;
use podssh_ws::turn::msg::{
    self, ALLOCATE, CONNECT, CONNECTION_BIND, CONNECTION_ID, LIFETIME, NONCE, REALM, XOR_PEER_ADDRESS,
    XOR_RELAYED_ADDRESS,
};
use podssh_ws::turn::{client, open, silent, Credentials, Dial, Opened, Server, TurnError};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How the stand-in answers.
#[derive(Clone, Copy)]
struct Plan {
    tcp: bool,
    lifetime: u32,
}

#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    refreshes: AtomicUsize,
    peers: Mutex<HashMap<u32, TcpStream>>,
}

const REALM_TEXT: &[u8] = b"podssh.test";
const PASSWORD: &str = "right-horse";

/// A TURN server on this host that takes `alice` with [`PASSWORD`] alone.
async fn stand_in(plan: Plan) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let shared = seen.clone();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            shared.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve(conn, plan, shared.clone()));
        }
    });
    (port, seen)
}

async fn serve(mut conn: TcpStream, plan: Plan, seen: Arc<Seen>) {
    let key = msg::long_term_key("alice", "podssh.test", PASSWORD);
    while let Ok(bytes) = client::read_message(&mut conn).await {
        let m = stun::parse(&bytes).unwrap();
        let method = m.kind & !msg::ERROR;
        let reply = |attrs: &[(u16, &[u8])]| msg::signed(msg::success(method), &m.id, attrs, Some(&key));
        let fail = |code: u16, extra: &[(u16, &[u8])]| {
            let mut attrs = vec![(msg::ERROR_CODE, error_value(code))];
            attrs.extend(extra.iter().map(|(k, v)| (*k, v.to_vec())));
            let attrs: Vec<(u16, &[u8])> = attrs.iter().map(|(k, v)| (*k, v.as_slice())).collect();
            stun::message(msg::error(method), &m.id, &attrs)
        };
        if msg::integrity(&bytes, &key) != Some(true) {
            let answer = fail(401, &[(REALM, REALM_TEXT), (NONCE, b"nonce-1")]);
            conn.write_all(&answer).await.unwrap();
            continue;
        }
        let answer = match method {
            ALLOCATE if !plan.tcp => fail(442, &[]),
            ALLOCATE => {
                let relayed = stun::write_address("192.0.2.7:49152".parse().unwrap(), Some(&m.id));
                reply(&[(XOR_RELAYED_ADDRESS, &relayed), (LIFETIME, &plan.lifetime.to_be_bytes())])
            }
            msg::REFRESH => {
                seen.refreshes.fetch_add(1, Ordering::SeqCst);
                reply(&[(LIFETIME, &plan.lifetime.to_be_bytes())])
            }
            CONNECT => {
                let peer = stun::read_address(m.attribute(XOR_PEER_ADDRESS).unwrap(), Some(&m.id)).unwrap();
                match TcpStream::connect(peer).await {
                    Ok(stream) => {
                        seen.peers.lock().unwrap().insert(7, stream);
                        reply(&[(CONNECTION_ID, &7u32.to_be_bytes())])
                    }
                    Err(_) => fail(447, &[]),
                }
            }
            CONNECTION_BIND => {
                let id = msg::u32_of(m.attribute(CONNECTION_ID).unwrap()).unwrap();
                let Some(mut peer) = seen.peers.lock().unwrap().remove(&id) else { return };
                conn.write_all(&reply(&[])).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut peer).await;
                return;
            }
            _ => fail(400, &[]),
        };
        conn.write_all(&answer).await.unwrap();
    }
}

fn error_value(code: u16) -> Vec<u8> {
    let mut v = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
    v.extend_from_slice(b"stand-in");
    v
}

/// A target that echoes each byte.
async fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn road(plan: Plan, password: &str) -> (Result<Opened, TurnError>, Arc<Seen>) {
    let (port, seen) = stand_in(plan).await;
    let server = Server::parse(&format!("turn:127.0.0.1:{port}")).unwrap();
    let credentials = Credentials::parse(&format!("alice:{password}")).unwrap();
    let target = echo().await;
    let dial =
        Dial { trust: &Trust::Default, proxy: &ProxyChoice::Direct, timeout: Duration::from_secs(5), note: silent() };
    (open(&server, &credentials, "127.0.0.1", target, &dial).await, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_road_carries_bytes_on_a_second_connection_and_refreshes_its_allocation() {
    let (opened, seen) = road(Plan { tcp: true, lifetime: 10 }, PASSWORD).await;
    let mut opened = opened.expect("the stand-in carries the road");
    assert_eq!(opened.lifetime, 10);
    assert_eq!(opened.relayed, Some("192.0.2.7:49152".parse().unwrap()));
    // The control connection and the data connection, to the same server.
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    let mut back = [0u8; 5];
    opened.stream.write_all(b"hello").await.unwrap();
    opened.stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"hello");
    // Past the half of the lifetime, the keeper refreshed it.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(seen.refreshes.load(Ordering::SeqCst) >= 1, "no Refresh came");
    opened.stream.write_all(b"again").await.unwrap();
    opened.stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"again");
}

#[tokio::test]
async fn a_server_with_no_tcp_allocation_and_a_wrong_password_are_said_so() {
    let (opened, _) = road(Plan { tcp: false, lifetime: 600 }, PASSWORD).await;
    let e = opened.err().expect("no TCP allocation");
    assert!(matches!(e, TurnError::NoTcp { code: 442, .. }), "{e:?}");
    assert!(e.line("turns:t.example").ends_with("the server offers no RFC 6062"), "{}", e.line("x"));
    let (opened, _) = road(Plan { tcp: true, lifetime: 600 }, "wrong-horse").await;
    let e = opened.err().expect("a wrong password");
    assert!(matches!(e, TurnError::Auth(_)), "{e:?}");
}
