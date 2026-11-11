//! A stand-in of ZeroTier's TCP relay and of a planet's root, for tests of
//! the road from end to end (feature `stand-in`; never in a release): a
//! listener on the loopback that speaks the relay's framing
//! (`crate::relay`), and gives each connection an address of its own on a
//! wire of memory, where a root of a planet of the stand-in's own waits. Each
//! end that the planet names as its world, and that dials this relay, meets
//! the others through that root, as through ZeroTier Inc.'s.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::member::{Datagram, Member, State, Wire};
use crate::relay::{encode, Records};

/// Each address on the wire, and its sender.
type Routes = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Datagram>>>>;

/// The root's address on the wire.
const ROOT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9993);

/// The stand-in, running until it is dropped.
pub struct StandIn {
    /// The relay's address on the loopback.
    pub relay: SocketAddr,
    /// The planet whose one root is the stand-in's.
    pub planet: Vec<u8>,
    _root: Member,
    accept: tokio::task::AbortHandle,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A wire on `routes` at `at`.
fn wire(routes: &Routes, at: SocketAddr) -> Wire {
    let (to_member, inbound) = mpsc::channel(1024);
    routes.lock().unwrap_or_else(|e| e.into_inner()).insert(at, to_member);
    let (out, mut from_member) = mpsc::channel::<Datagram>(1024);
    let routes = routes.clone();
    tokio::spawn(async move {
        while let Some((to, bytes)) = from_member.recv().await {
            let next = routes.lock().unwrap_or_else(|e| e.into_inner()).get(&to).cloned();
            if let Some(next) = next {
                let _ = next.send((at, bytes)).await;
            }
        }
    });
    Wire { out, inbound }
}

/// Start the stand-in on the runtime of the caller.
pub async fn start() -> Result<StandIn, String> {
    let routes: Routes = Arc::default();
    // The root's identity first, then the planet that names it, then the
    // root again with its planet.
    let state: Arc<Mutex<State>> = Arc::default();
    drop(Member::start(state.clone(), wire(&routes, ROOT.into()), None)?);
    let public = state.lock().unwrap_or_else(|e| e.into_inner()).public.clone().ok_or("the root has no identity")?;
    let planet = crate::world(149_604_618, 1_800_000_000_000, &[(public.as_str(), "10.0.0.1/9993")])?;
    state.lock().unwrap_or_else(|e| e.into_inner()).planet = Some(planet.clone());
    let root = Member::start(state, wire(&routes, ROOT.into()), None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let relay = listener.local_addr().map_err(|e| e.to_string())?;
    let accept = tokio::spawn(async move {
        let mut next = 2u32;
        while let Ok((tcp, _)) = listener.accept().await {
            let at = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0x0a01_0000 + next), 9993));
            next += 1;
            tokio::spawn(carry(tcp, at, routes.clone()));
        }
    });
    Ok(StandIn { relay, planet, _root: root, accept: accept.abort_handle() })
}

/// One connection of the relay: its records go on the wire from `at`, and
/// what the wire sends to `at` goes back as records.
async fn carry(tcp: tokio::net::TcpStream, at: SocketAddr, routes: Routes) {
    let (mut read, mut write) = tcp.into_split();
    let Wire { out, mut inbound } = wire(&routes, at);
    let back = tokio::spawn(async move {
        while let Some((from, datagram)) = inbound.recv().await {
            let SocketAddr::V4(from) = from else { continue };
            let Ok(record) = encode(from, &datagram) else { continue };
            if write.write_all(&record).await.is_err() {
                return;
            }
        }
    });
    let (mut records, mut buf) = (Records::default(), vec![0u8; 65536]);
    while let Ok(n) = read.read(&mut buf).await {
        if n == 0 {
            break;
        }
        // The HELLO and each record of another form carry no datagram.
        for (to, datagram) in records.push(&buf[..n]) {
            if out.send((SocketAddr::V4(to), datagram)).await.is_err() {
                break;
            }
        }
    }
    routes.lock().unwrap_or_else(|e| e.into_inner()).remove(&at);
    back.abort();
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::pair::PairRoad;
    use crate::road::{self, Dial};

    /// Each dial a TCP connection to the stand-in's relay.
    fn dial(relay: std::net::SocketAddr) -> Dial {
        std::sync::Arc::new(move || {
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(relay).await.map_err(|e| e.to_string())?;
                Ok(road::relay_wire(tcp))
            })
        })
    }

    /// The pair's road on TCP through the stand-in's relay and root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pair_s_road_runs_through_the_stand_in_s_relay() {
        let stand_in = super::start().await.unwrap();
        let mut made = PairRoad::of("lab", "token-one").unwrap();
        made.planet = Some(stand_in.planet.clone());
        let (visitors, mut came) = tokio::sync::mpsc::channel(4);
        tokio::spawn(road::serve(made.clone(), dial(stand_in.relay), visitors, std::sync::Arc::new(|_| {})));
        tokio::spawn(async move {
            let (mut conn, _) = came.recv().await.unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut link = road::link(&made, &dial(stand_in.relay), Duration::from_secs(30)).await.unwrap();
        link.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(30), link.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"hello");
    }
}
