//! Two members and a root in one process, on a wire of memory that a task
//! routes by address: a TCP connection over the ad-hoc network, from one
//! member's stack to a listener of the other's, carries 64 KiB each way.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::*;

const NWID: u64 = 0xff00_01ff_ff00_0000;

/// The wire of memory: each member's sender, by its address.
type Routes = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Datagram>>>>;

/// A member at `at` on the wire of `routes`.
fn member(routes: &Routes, at: &str, state: Arc<Mutex<State>>, network: Option<u64>) -> Member {
    let at: SocketAddr = at.parse().unwrap();
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
    Member::start(state, Wire { out, inbound }, network).expect("a member")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_connection_over_the_ad_hoc_network_carries_64_kib_each_way() {
    let routes: Routes = Arc::default();
    let root_state: Arc<Mutex<State>> = Arc::default();
    let first = member(&routes, "10.0.0.1:9993", root_state.clone(), None);
    drop(first);
    let public = root_state.lock().unwrap().public.clone().expect("the root's identity");
    let planet = crate::world(149_604_618, 1_800_000_000_000, &[(public.as_str(), "10.0.0.1/9993")]).unwrap();
    root_state.lock().unwrap().planet = Some(planet.clone());
    let with_planet = || Arc::new(Mutex::new(State { planet: Some(planet.clone()), ..State::default() }));
    let _root = member(&routes, "10.0.0.1:9993", root_state, None);
    let a = member(&routes, "10.0.0.2:9993", with_planet(), Some(NWID));
    let b = member(&routes, "10.0.0.3:9993", with_planet(), Some(NWID));
    let at = SocketAddr::new(IpAddr::V6(sixplane(NWID, b.address)), 22);
    let mut listener = b.stack.as_ref().unwrap().listen(at).await.unwrap();
    tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        conn.read_exact(&mut buf).await.unwrap();
        conn.write_all(&buf).await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let connected = crate::road::connect(&a, at, Duration::from_secs(30)).await;
    let mut conn = connected.expect("a connection over the network");
    let sent: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    conn.write_all(&sent).await.unwrap();
    let mut got = vec![0u8; 65536];
    tokio::time::timeout(Duration::from_secs(60), conn.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(got, sent);
}
