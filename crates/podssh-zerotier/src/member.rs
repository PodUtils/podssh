//! A member of ZeroTier's road (T-733): a node of the core driven by one
//! task of this process, with TCP over its ad-hoc network on WARP's stack of
//! smoltcp (`podssh_warp::stack`). The network carries IPv6 alone, each
//! member at its 6plane address, which holds the member's ZeroTier address;
//! so a packet's frame goes to the MAC of the address in its destination,
//! and no neighbour discovery is needed. The wire is two channels, which the
//! caller carries: the TCP relay (`crate::relay`), or a test's memory. A
//! root of a planet runs as a member of no network.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_warp::stack::{Link, Stack, Why};
use tokio::sync::mpsc;

use crate::node::{mac_of, Host, Node};
use crate::state;

/// A datagram of the wire: whom it is to, or from, and its bytes.
pub type Datagram = (SocketAddr, Vec<u8>);

/// The packets that wait in each direction.
const QUEUE: usize = 1024;
/// The longest that the task sleeps between the core's timers.
const MOST_SLEEP: Duration = Duration::from_millis(500);

/// What a member keeps: its identity, which the core made, and the planet.
#[derive(Debug, Default)]
pub struct State {
    pub identity: Option<Vec<u8>>,
    pub public: Option<String>,
    pub planet: Option<Vec<u8>>,
}

/// The wire of a member: what it sends, and what comes to it.
pub struct Wire {
    pub out: mpsc::Sender<Datagram>,
    pub inbound: mpsc::Receiver<Datagram>,
}

/// The 6plane address of `address` on `nwid` (`InetAddress::makeIpv66plane`).
pub fn sixplane(nwid: u64, address: u64) -> Ipv6Addr {
    let n = (nwid ^ (nwid >> 32)) as u32;
    let mut out = [0u8; 16];
    out[0] = 0xfc;
    out[1..5].copy_from_slice(&n.to_be_bytes());
    out[5..10].copy_from_slice(&address.to_be_bytes()[3..8]);
    out[15] = 1;
    Ipv6Addr::from(out)
}

/// The ZeroTier address in a 6plane address.
fn address_of(ip: &Ipv6Addr) -> u64 {
    let o = ip.octets();
    o[5..10].iter().fold(0u64, |a, b| (a << 8) | u64::from(*b))
}

struct Glue {
    wire: mpsc::Sender<Datagram>,
    packets: Option<mpsc::Sender<Vec<u8>>>,
    state: Arc<Mutex<State>>,
}

impl Host for Glue {
    fn wire(&mut self, to: SocketAddr, packet: &[u8]) {
        // A full wire drops, as UDP does; the core sends again.
        let _ = self.wire.try_send((to, packet.to_vec()));
    }
    fn frame(&mut self, _: u64, _: u64, _: u64, ether_type: u16, data: &[u8]) {
        if let (0x86dd, Some(packets)) = (ether_type, &self.packets) {
            let _ = packets.try_send(data.to_vec());
        }
    }
    fn put(&mut self, kind: i32, data: Option<&[u8]>) {
        let mut kept = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match kind {
            state::IDENTITY_SECRET => kept.identity = data.map(<[u8]>::to_vec),
            state::IDENTITY_PUBLIC => kept.public = data.map(|d| String::from_utf8_lossy(d).trim().to_string()),
            _ => {}
        }
    }
    fn get(&mut self, kind: i32) -> Option<Vec<u8>> {
        let kept = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match kind {
            state::PLANET => kept.planet.clone(),
            state::IDENTITY_SECRET => kept.identity.clone(),
            _ => None,
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A member running: its address, and its stack on `network` if it joined one.
pub struct Member {
    pub address: u64,
    pub stack: Option<Stack>,
    task: tokio::task::AbortHandle,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Member {
    /// Start a member with `state` on `wire`, joined to `network` if given,
    /// on the runtime of the caller.
    pub fn start(state: Arc<Mutex<State>>, wire: Wire, network: Option<u64>) -> Result<Member, String> {
        let (packets_in, inbound) = mpsc::channel(QUEUE);
        let (out, mut packets_out) = mpsc::channel::<Vec<u8>>(QUEUE);
        let glue = Glue { wire: wire.out, packets: network.map(|_| packets_in), state };
        let mut node = Node::new(Box::new(glue), now_ms())?;
        if let Some(nwid) = network {
            node.join(nwid)?;
        }
        let address = node.address();
        let why = Why::default();
        let (mut wire_in, ended) = (wire.inbound, why.clone());
        let task = tokio::spawn(async move {
            let mut running = true;
            while running {
                let sleep =
                    Duration::from_millis((node.next - now_ms()).clamp(1, MOST_SLEEP.as_millis() as i64) as u64);
                tokio::select! {
                    got = wire_in.recv() => match got {
                        Some((from, bytes)) => running = node.wire(now_ms(), from, &bytes).is_ok(),
                        None => running = false,
                    },
                    packet = packets_out.recv(), if network.is_some() => match (packet, network) {
                        (Some(packet), Some(nwid)) => {
                            if let Some(dest) = destination(&packet) {
                                let (src, dst) = (mac_of(node.address(), nwid), mac_of(address_of(&dest), nwid));
                                running = node.frame(now_ms(), nwid, src, dst, 0x86dd, &packet).is_ok();
                            }
                        }
                        _ => running = false,
                    },
                    () = tokio::time::sleep(sleep) => running = node.background(now_ms()).is_ok(),
                }
            }
            ended.set("ZeroTier's node ended");
        });
        let stack = match network {
            Some(nwid) => {
                let link = Link { out, inbound, why, tasks: Vec::new(), flow: Arc::default() };
                Some(Stack::start(&[IpAddr::V6(sixplane(nwid, address))], link)?)
            }
            None => None,
        };
        Ok(Member { address, stack, task: task.abort_handle() })
    }
}

/// The destination of an IPv6 packet.
fn destination(packet: &[u8]) -> Option<Ipv6Addr> {
    let bytes: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    (packet[0] >> 4 == 6).then(|| Ipv6Addr::from(bytes))
}

#[cfg(test)]
#[path = "member_tests.rs"]
mod tests;
