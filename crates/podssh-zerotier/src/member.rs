//! A member of ZeroTier's road (T-733): a node of the core driven by one
//! task of this process, with TCP over its ad-hoc network on the userspace
//! stack of `pod-netstack` (smoltcp). The network carries IPv6 alone, each
//! member at its 6plane address, which holds the member's ZeroTier address;
//! so a packet's frame goes to the MAC of the address in its destination,
//! and no neighbour discovery is needed. The wire is two channels, which the
//! caller carries: the TCP relay (`crate::relay`), or a test's memory. A
//! root of a planet runs as a member of no network.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pod_netstack::{NetStack, PacketQueue, StackConfig, Subnet};
use tokio::sync::{mpsc, Notify};

use crate::node::{mac_of, Host, Node};
use crate::state;

/// A datagram of the wire: whom it is to, or from, and its bytes.
pub type Datagram = (SocketAddr, Vec<u8>);

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
    /// The queue into the stack, once the member has its address.
    packets: Option<Arc<OnceLock<PacketQueue>>>,
    state: Arc<Mutex<State>>,
    trace: Arc<crate::trace::Trace>,
}

impl Host for Glue {
    fn wire(&mut self, to: SocketAddr, packet: &[u8]) {
        self.trace.sent(to);
        // A full wire drops, as UDP does; the core sends again.
        let _ = self.wire.try_send((to, packet.to_vec()));
    }
    fn frame(&mut self, _: u64, _: u64, _: u64, ether_type: u16, data: &[u8]) {
        self.trace.frame_in();
        // A full queue drops, as a link does; TCP sends again.
        if let (0x86dd, Some(packets)) = (ether_type, self.packets.as_ref().and_then(|p| p.get())) {
            let _ = packets.push(data.to_vec());
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

/// Why a member's node ended, once it has, and a wake of each waiter.
#[derive(Clone, Default)]
struct Ended(Arc<(OnceLock<String>, Notify)>);

impl Ended {
    /// Set the cause (the first stays), and wake each waiter.
    fn set(&self, why: &str) {
        let _ = self.0 .0.set(why.to_string());
        self.0 .1.notify_waiters();
    }

    fn get(&self) -> Option<String> {
        self.0 .0.get().cloned()
    }

    async fn wait(&self) {
        loop {
            let notified = self.0 .1.notified();
            tokio::pin!(notified);
            // Register first: an end between the check and the wait is not
            // lost.
            notified.as_mut().enable();
            if self.get().is_some() {
                return;
            }
            notified.await;
        }
    }
}

/// The address plan of a member's stack on `nwid`: the 6plane prefix of
/// the network (40 bits: `fc` and the network's 32 bits), so that each
/// member's address is on the link, and `ours`, the member's address.
fn stack_config(nwid: u64, ours: Ipv6Addr) -> StackConfig {
    let mut prefix = sixplane(nwid, 0).octets();
    prefix[5..].fill(0);
    let subnet = Subnet { v6: Ipv6Addr::from(prefix), v6_prefix: 40, ..Subnet::default() };
    StackConfig { subnet, local_v6: ours, ..StackConfig::default() }
}

/// A member running: its address, and its stack on `network` if it joined one.
pub struct Member {
    pub address: u64,
    pub stack: Option<NetStack>,
    ended: Ended,
    task: tokio::task::AbortHandle,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Member {
    /// Why the member's node ended, once it has.
    pub fn ended(&self) -> Option<String> {
        self.ended.get()
    }

    /// Wait for the end of the member's node.
    pub async fn closed(&self) {
        self.ended.wait().await
    }

    /// Start a member with `state` on `wire`, joined to `network` if given,
    /// on the runtime of the caller.
    pub fn start(state: Arc<Mutex<State>>, wire: Wire, network: Option<u64>) -> Result<Member, String> {
        let trace = crate::trace::Trace::from_env();
        let into_stack: Arc<OnceLock<PacketQueue>> = Arc::default();
        let packets = network.map(|_| into_stack.clone());
        let glue = Glue { wire: wire.out, packets, state, trace: trace.clone() };
        let mut node = Node::new(Box::new(glue), now_ms())?;
        if let Some(nwid) = network {
            node.join(nwid)?;
        }
        let address = node.address();
        trace.start(address);
        // The stack's link: the frames of the network go into its queue in,
        // and each packet of its queue out goes to the network as a frame.
        let stack = network.map(|nwid| NetStack::over_link(stack_config(nwid, sixplane(nwid, address))));
        let from_stack = stack.as_ref().map(|stack| {
            let _ = into_stack.set(stack.link_in());
            stack.link_out()
        });
        let reset = stack.as_ref().map(NetStack::resetter);
        let ended = Ended::default();
        let (mut wire_in, end) = (wire.inbound, ended.clone());
        let task = tokio::spawn(async move {
            let mut running = true;
            while running {
                let sleep =
                    Duration::from_millis((node.next - now_ms()).clamp(1, MOST_SLEEP.as_millis() as i64) as u64);
                tokio::select! {
                    got = wire_in.recv() => match got {
                        Some((from, bytes)) => {
                            trace.came(from);
                            running = node.wire(now_ms(), from, &bytes).is_ok();
                        }
                        None => running = false,
                    },
                    packet = next_out(&from_stack) => match (packet, network) {
                        (Some(packet), Some(nwid)) => {
                            if let Some(dest) = destination(&packet) {
                                trace.frame_out();
                                let (src, dst) = (mac_of(node.address(), nwid), mac_of(address_of(&dest), nwid));
                                running = node.frame(now_ms(), nwid, src, dst, 0x86dd, &packet).is_ok();
                            }
                        }
                        _ => running = false,
                    },
                    () = tokio::time::sleep(sleep) => running = node.background(now_ms()).is_ok(),
                }
            }
            // Each connection on the stack ends with the node's cause.
            if let Some(reset) = reset {
                reset.reset("ZeroTier's node ended");
            }
            end.set("ZeroTier's node ended");
        });
        Ok(Member { address, stack, ended, task: task.abort_handle() })
    }
}

/// The next packet of the stack's queue out; with no stack, never.
async fn next_out(queue: &Option<PacketQueue>) -> Option<Vec<u8>> {
    match queue {
        Some(queue) => Some(queue.recv().await),
        None => std::future::pending().await,
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
