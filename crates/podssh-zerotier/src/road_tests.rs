//! The pair's road on a wire of memory with a root of the test's own: the
//! node serves, a client links to it and carries 64 KiB each way; the node
//! dials again after its wire ended; a client of another pair reaches no
//! node.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::member::Datagram;

/// The wire of memory: each member's sender, by its address.
type Routes = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Datagram>>>>;

/// A wire at `at`, routed by `routes`.
fn wire(routes: &Routes, at: SocketAddr) -> Wire {
    let (to_member, inbound) = mpsc::channel(1024);
    routes.lock().unwrap().insert(at, to_member);
    let (out, mut from_member) = mpsc::channel::<Datagram>(1024);
    let routes = routes.clone();
    tokio::spawn(async move {
        while let Some((to, bytes)) = from_member.recv().await {
            let next = routes.lock().unwrap().get(&to).cloned();
            if let Some(next) = next {
                let _ = next.send((at, bytes)).await;
            }
        }
    });
    Wire { out, inbound }
}

/// Each dial a new address on the wire, as each TCP connection to the relay
/// is; the first `drop_first` dials end their wire at once.
fn dial(routes: &Routes, base: u32, drop_first: usize) -> (Dial, Arc<AtomicUsize>) {
    let (routes, next, count) = (routes.clone(), Arc::new(AtomicU32::new(0)), Arc::new(AtomicUsize::new(0)));
    let counted = count.clone();
    let dial: Dial = Arc::new(move || {
        let n = next.fetch_add(1, Ordering::SeqCst);
        let at = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(base + n)), 9993);
        let dialed = counted.fetch_add(1, Ordering::SeqCst);
        let mut made = wire(&routes, at);
        if dialed < drop_first {
            let (_gone, closed) = mpsc::channel(1);
            made.inbound = closed;
        }
        Box::pin(async move { Ok(made) })
    });
    (dial, count)
}

/// A root on `routes` at 10.0.0.1, and the planet whose root it is.
fn root(routes: &Routes) -> (Member, Vec<u8>) {
    let at: SocketAddr = "10.0.0.1:9993".parse().unwrap();
    let state: Arc<Mutex<State>> = Arc::default();
    drop(Member::start(state.clone(), wire(routes, at), None).unwrap());
    let public = state.lock().unwrap().public.clone().expect("the root's identity");
    let planet = crate::world(149_604_618, 1_800_000_000_000, &[(public.as_str(), "10.0.0.1/9993")]).unwrap();
    state.lock().unwrap().planet = Some(planet.clone());
    (Member::start(state, wire(routes, at), None).unwrap(), planet)
}

fn quiet() -> Say {
    Arc::new(|_| {})
}

/// The node of `road`, whose first `drop_first` wires end at once; each
/// connection echoes 64 KiB.
fn node(routes: &Routes, road: &PairRoad, drop_first: usize) -> Arc<AtomicUsize> {
    let (dial, count) = dial(routes, 0x0a00_0100, drop_first);
    let (visitors, mut came) = mpsc::channel(8);
    tokio::spawn(serve(road.clone(), dial, visitors, quiet()));
    tokio::spawn(async move {
        while let Some((mut conn, _)) = came.recv().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                conn.read_exact(&mut buf).await.unwrap();
                conn.write_all(&buf).await.unwrap();
                conn.flush().await.unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    count
}

async fn carry(link: &mut Link) {
    let sent: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    link.write_all(&sent).await.unwrap();
    let mut got = vec![0u8; 65536];
    tokio::time::timeout(Duration::from_secs(60), link.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(got, sent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_links_to_the_node_of_its_pair_after_the_node_dialed_again() {
    let routes: Routes = Arc::default();
    let (_root, planet) = root(&routes);
    let mut road = PairRoad::of("lab", "token-one").unwrap();
    road.planet = Some(planet);
    let dials = node(&routes, &road, 1);
    let (client, _) = dial(&routes, 0x0a00_0200, 0);
    let mut link = link(&road, &client, Duration::from_secs(30), Default::default()).await.expect("a link to the node");
    carry(&mut link).await;
    assert!(dials.load(Ordering::SeqCst) >= 2, "the node dialed again after its first wire ended");

    // A client of another pair: another network, another node, none there.
    let mut other = PairRoad::of("lab", "token-two").unwrap();
    other.planet = road.planet.clone();
    let (stranger, _) = dial(&routes, 0x0a00_0300, 0);
    assert!(super::link(&other, &stranger, Duration::from_secs(10), Default::default()).await.is_err());
}

/// A client's identity is the caller's: one kept from an earlier link is
/// used again, and the one that the core made is left in the state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_keeps_its_identity_from_one_link_to_the_next() {
    let routes: Routes = Arc::default();
    let (_root, planet) = root(&routes);
    let mut road = PairRoad::of("lab", "token-one").unwrap();
    road.planet = Some(planet);
    node(&routes, &road, 0);
    let (client, _) = dial(&routes, 0x0a00_0400, 0);
    let first: Arc<Mutex<State>> = Arc::default();
    drop(link(&road, &client, Duration::from_secs(30), first.clone()).await.expect("a first link"));
    let made = first.lock().unwrap().identity.clone().expect("the core made an identity");
    let again = Arc::new(Mutex::new(State { identity: Some(made.clone()), ..State::default() }));
    drop(link(&road, &client, Duration::from_secs(30), again.clone()).await.expect("a second link"));
    assert_eq!(again.lock().unwrap().identity.as_ref(), Some(&made), "the kept identity, not a new one");
}

#[test]
fn the_backoff_doubles_to_a_minute() {
    let waits: Vec<u64> = (0..9).map(|n| backoff(n).as_secs()).collect();
    assert_eq!(waits, [0, 1, 2, 4, 8, 16, 32, 32, 32]);
}
