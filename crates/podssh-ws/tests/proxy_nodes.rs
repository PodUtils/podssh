//! The round over the public proxy nodes of a list (T-574) against the VLESS
//! stand-ins of `vless_support/` on the loopback, which follow Xray-core's
//! server (`scripts/interop-vless.sh` runs the real one): a node that refuses
//! the ID, a Trojan node that nobody listens at and a VLESS node that nobody
//! listens at give way, in order, to the node that carries the target's
//! version line; at most the asked number of nodes is tried; a node that says
//! nothing gives way at its bound; and no line of a failure holds an ID or a
//! password. The filters and the reading of a list are unit tests of
//! `podssh_ws::proxy_nodes`.

mod vless_support;

use std::time::Duration;

use podssh_ws::proxy_nodes::{carry, Dial, Node};
use podssh_ws::vless::{self, AtEnd, Server};
use podssh_ws::{trojan, ProxyChoice, Trust};
use tokio::io::AsyncReadExt;
use vless_support::{pins, root_file, target, ws_server, BANNER, ID, NAME};

const LIMIT: Duration = Duration::from_secs(20);
const OTHER: &str = "00000000-0000-4000-8000-000000000001";

fn vless_node(port: u16, id: &str) -> Node {
    let link = format!("vless://{id}@{NAME}:{port}?type=ws&security=tls&path=%2Fws");
    Node::Vless(Server::parse(&link).unwrap())
}

/// A port that nobody listens at.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn dial<'a>(trust: &'a Trust, proxy: &'a ProxyChoice) -> Dial<'a> {
    Dial { trust, proxy, timeout: LIMIT, answer: vless::ANSWER_WAIT, silence_is_ready: false, at_end: AtEnd::Now }
}

/// The first nodes fail, each in its own words; the last carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_round_goes_on_past_a_refusal_and_a_dead_node_to_the_node_that_carries() {
    pins();
    let (root, aim) = (root_file("round"), target(true).await);
    let (port, seen) = ws_server().await;
    let trojan_link = format!("trojan://a-pw@{NAME}:{}?security=tls", closed_port());
    let nodes = vec![
        vless_node(port, OTHER),
        Node::Trojan(trojan::Server::parse(&trojan_link).unwrap()),
        vless_node(closed_port(), ID),
        vless_node(port, ID),
    ];
    let (trust, proxy) = (Trust::File(root.to_path_buf()), ProxyChoice::Direct);
    let dialed = dial(&trust, &proxy);
    let mut said: Vec<String> = Vec::new();
    let mut say = |line: &str| said.push(line.to_string());
    let round = carry(&nodes, "127.0.0.1", aim, &dialed, (LIMIT, 8), &mut say);
    let carried = tokio::time::timeout(LIMIT * 4, round)
        .await
        .expect("within the limit")
        .unwrap_or_else(|lines| panic!("no node carried: {lines:?}"));
    assert_eq!(carried.how, "a WebSocket");
    assert_eq!(carried.node, nodes[3]);
    let mut stream = carried.stream;
    let mut banner = vec![0u8; BANNER.len()];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut banner)).await.expect("the banner in time").unwrap();
    assert_eq!(banner, BANNER);
    assert_eq!(*seen.targets.lock().unwrap(), vec![format!("127.0.0.1:{aim}")]);
    assert_eq!(said.len(), 3, "one line for each node that failed: {said:?}");
    assert!(said[0].contains("refused the ID"), "{}", said[0]);
    assert!(said[1].contains("the Trojan server trojan://"), "{}", said[1]);
    for line in &said {
        assert!(!line.contains(OTHER) && !line.contains(ID) && !line.contains("a-pw"), "a credential in {line}");
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// Only `most` nodes are tried, and each failure is returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_more_than_the_asked_number_of_nodes_is_tried() {
    pins();
    let (root, aim) = (root_file("most"), target(true).await);
    let (port, seen) = ws_server().await;
    let nodes = vec![vless_node(port, OTHER), vless_node(port, OTHER), vless_node(port, ID)];
    let (trust, proxy) = (Trust::File(root.to_path_buf()), ProxyChoice::Direct);
    let dialed = dial(&trust, &proxy);
    let mut say = |_: &str| {};
    let failed = carry(&nodes, "127.0.0.1", aim, &dialed, (LIMIT, 2), &mut say).await;
    let lines = failed.err().expect("the third node was never tried");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(seen.targets.lock().unwrap().is_empty(), "a refused ID reaches no target");
    // A list with no node is no round: nothing to say, nothing carried.
    let none = carry(&[], "127.0.0.1", aim, &dialed, (LIMIT, 2), &mut say).await;
    assert!(none.err().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A node that holds the connection and says nothing gives way at the bound
/// of each node, not at the dial's much longer one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_that_says_nothing_gives_way_at_the_bound_of_each() {
    pins();
    let root = root_file("silent");
    // Accepts the TCP connection and says nothing: TLS never starts.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    let (trust, proxy) = (Trust::File(root.to_path_buf()), ProxyChoice::Direct);
    let dialed = dial(&trust, &proxy);
    let mut say = |_: &str| {};
    let started = std::time::Instant::now();
    let each = (Duration::from_secs(1), 1);
    let failed = carry(&[vless_node(port, ID)], "127.0.0.1", 22, &dialed, each, &mut say).await;
    let lines = failed.err().expect("no session");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(lines[0].contains("gave no session within 1 s"), "{}", lines[0]);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}
