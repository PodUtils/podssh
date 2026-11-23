//! iroh's relay protocol at podssh's relay role (T-720), against clients of
//! n0's own code (iroh-relay's `ClientBuilder`, the client that each iroh
//! endpoint runs), on the loopback over plain TCP, as the role serves each
//! request behind its TLS: two clients meet and carry 1 MiB each way; of
//! three, a datagram reaches the key that it names alone; the probes answer
//! as iroh-relay's server answers; and a role that mints for a list admits
//! its keys alone. Its own binary: the road is turned on for the process.
#![cfg(feature = "iroh-serve")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::client::{Client, ClientBuilder};
use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
use iroh_relay::tls::{default_provider, CaTlsConfig};
use n0_future::{SinkExt, StreamExt};
use podssh_relay::identity::Identity;
use podssh_relay::serve::keys::List;
use podssh_relay::serve::{self, meet, Config, Mint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LIMIT: Duration = Duration::from_secs(20);
/// What a client sends until its peer is up: iroh-relay drops a datagram to
/// a key that is not registered yet.
const HELLO: &[u8] = b"hello";

/// The role on a free port of the loopback, with iroh's road on; its URL as
/// an iroh endpoint names a relay, and its events.
async fn role(mint: Mint) -> (RelayUrl, Arc<Mutex<Vec<String>>>) {
    meet::enable_iroh();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let said = events.clone();
    let say: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint,
        tokens: serve::tokens::Tokens::new([5; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: None,
        events: Some(say),
    });
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            tokio::spawn(serve::serve_from(tcp, cfg.clone(), None, Some(peer.ip())));
        }
    });
    let url = format!("http://127.0.0.1:{port}").parse().expect("the role's URL");
    (url, events)
}

/// A client of n0's code with the key of `seed`, as an endpoint dials its
/// relay: `Err` with iroh's words when the relay refuses it.
async fn client(url: &RelayUrl, seed: u8) -> Result<Client, String> {
    let tls = CaTlsConfig::default().client_config(default_provider()).expect("a TLS configuration");
    let builder = ClientBuilder::new(url.clone(), SecretKey::from_bytes(&[seed; 32]), DnsResolver::new());
    let connected = tokio::time::timeout(LIMIT, builder.tls_client_config(tls).connect()).await;
    connected.expect("a handshake in time").map_err(|e| format!("{e:#}"))
}

fn id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

async fn send(from: &mut Client, to: EndpointId, payload: &[u8]) {
    let datagram = ClientToRelayMsg::Datagrams { dst_endpoint_id: to, datagrams: Datagrams::from(payload) };
    from.send(datagram).await.expect("the relay takes a datagram");
}

/// The next datagram of `client` past the hellos: its sender and its bytes.
async fn datagram(client: &mut Client) -> (EndpointId, Vec<u8>) {
    loop {
        match tokio::time::timeout(LIMIT, client.next()).await.expect("a datagram in time") {
            Some(Ok(RelayToClientMsg::Datagrams { remote_endpoint_id, datagrams })) => {
                if datagrams.contents.as_ref() != HELLO {
                    return (remote_endpoint_id, datagrams.contents.to_vec());
                }
            }
            Some(Ok(_)) => {}
            other => panic!("the relay ended the client: {other:?}"),
        }
    }
}

/// Until `to` hears `from`: a hello each 50 ms, as `to` may not be
/// registered when its handshake ends. One read of `to` stays pending
/// beside the hellos: a read dropped midway can lose its frame, which a
/// slow host met (the gate's `libs` at `abebb7c`).
async fn meet(from: &mut Client, to: &mut Client, to_id: EndpointId) {
    let deadline = tokio::time::Instant::now() + LIMIT;
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        let next = to.next();
        tokio::pin!(next);
        let got = loop {
            tokio::select! {
                got = &mut next => break got,
                _ = tick.tick() => {
                    assert!(tokio::time::Instant::now() < deadline, "the two clients never met through the role");
                    send(from, to_id, HELLO).await;
                }
            }
        };
        match got {
            Some(Ok(RelayToClientMsg::Datagrams { .. })) => return,
            Some(Ok(_)) => {}
            other => panic!("the relay ended the client: {other:?}"),
        }
    }
}

/// 18 datagrams of 60000 bytes from `from` to `to`: past 1 MiB, each under
/// iroh's 64 KiB, each whole, in order and naming its sender.
async fn carry(from: &mut Client, to: &mut Client, to_id: EndpointId, from_id: EndpointId) {
    let mut carried = 0;
    for n in 0..18u8 {
        send(from, to_id, &vec![n; 60_000]).await;
        let (sender, bytes) = datagram(to).await;
        assert_eq!(sender, from_id, "the datagram names its sender");
        assert!(bytes.len() == 60_000 && bytes.iter().all(|b| *b == n), "datagram {n} came whole");
        carried += bytes.len();
    }
    assert!(carried >= 1 << 20, "{carried} bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_of_iroh_relay_meet_through_the_role_and_carry_1_mib_each_way() {
    let (url, events) = role(Mint::Anyone).await;
    let (mut a, mut b) = (client(&url, 1).await.expect("a"), client(&url, 2).await.expect("b"));
    meet(&mut a, &mut b, id(2)).await;
    meet(&mut b, &mut a, id(1)).await;
    carry(&mut a, &mut b, id(2), id(1)).await;
    carry(&mut b, &mut a, id(1), id(2)).await;
    let said = events.lock().unwrap().clone();
    assert_eq!(said.iter().filter(|l| l.starts_with("iroh: the endpoint ") && l.ends_with(" is up")).count(), 2);
}

// Each test its own keys: the role's registry of iroh's clients is the
// process's, and a key that comes again takes the place of the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn of_three_clients_a_datagram_reaches_the_key_that_it_names_alone() {
    let (url, _) = role(Mint::Anyone).await;
    let mut a = client(&url, 11).await.expect("a");
    let mut b = client(&url, 12).await.expect("b");
    let mut c = client(&url, 13).await.expect("c");
    meet(&mut a, &mut b, id(12)).await;
    meet(&mut a, &mut c, id(13)).await;
    send(&mut a, id(13), b"for c").await;
    send(&mut a, id(12), b"for b").await;
    assert_eq!(datagram(&mut b).await, (id(11), b"for b".to_vec()), "B got a datagram that named another key");
    assert_eq!(datagram(&mut c).await, (id(11), b"for c".to_vec()), "C got a datagram that named another key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_that_mints_for_a_list_admits_its_keys_alone_with_iroh_s_denial() {
    let dir = std::env::temp_dir().join(format!("podssh-relay-meet-{}", std::process::id()));
    podssh_relay::cache::private_dir(&dir).unwrap();
    let path = dir.join("allow");
    let listed = Identity::from_seed(&[21; 32]).public().fingerprint();
    std::fs::write(&path, format!("{listed} the listed endpoint\n")).unwrap();
    let (url, events) = role(Mint::Keys(List::File(path))).await;
    client(&url, 21).await.expect("a listed key");
    let why = client(&url, 22).await.expect_err("a key off the list is refused");
    assert!(why.contains("not authorized"), "{why}");
    let refused = Identity::from_seed(&[22; 32]).public().fingerprint();
    let said = events.lock().unwrap().clone();
    assert!(said.iter().any(|l| l.starts_with(&format!("iroh: refused the endpoint {refused}"))), "{said:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// One request's head of the answer, on the loopback.
async fn head_of(url: &RelayUrl, request: &str) -> String {
    let port = url.port().expect("a port");
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probes_and_a_bad_upgrade_answer_as_iroh_relay_s_server() {
    let (url, _) = role(Mint::Anyone).await;
    let ping = head_of(&url, "GET /ping HTTP/1.1\r\nHost: r\r\n\r\n").await;
    assert!(ping.starts_with("HTTP/1.1 200 ") && ping.contains("Access-Control-Allow-Origin: *"), "{ping}");
    let asked = "GET /generate_204 HTTP/1.1\r\nHost: r\r\nX-Iroh-Challenge: abc\r\n\r\n";
    let no_content = head_of(&url, asked).await;
    let answered = no_content.contains("X-Iroh-Response: response abc");
    assert!(no_content.starts_with("HTTP/1.1 204 ") && answered, "{no_content}");
    // An upgrade with no version of the protocol: 400, as iroh-relay says.
    let upgrade = "GET /relay HTTP/1.1\r\nHost: r\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let refused = head_of(&url, upgrade).await;
    assert!(refused.starts_with("HTTP/1.1 400 ") && refused.contains("iroh-relay-v2"), "{refused}");
    // `/relays.json` names the road, so that a member lists this host first.
    let doc = head_of(&url, "GET /relays.json HTTP/1.1\r\nHost: relay.test:8443\r\n\r\n").await;
    assert!(doc.contains(r#""iroh":"https://relay.test:8443/""#), "{doc}");
}
