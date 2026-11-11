//! Three nodes of the core in one process, on a wire of memory and a clock
//! of the test's own: a root of a planet made here, and two members of an
//! ad-hoc network (`ff` + its port range + `000000`), which no controller
//! configures. One member sends the other an IPv6 UDP frame, and it comes
//! out of the other's core whole.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::node::{Host, Node};
use crate::state;

/// The ad-hoc network of every port: `ff`, ports 1 to 0xffff, `000000`.
const NWID: u64 = 0xff00_01ff_ff00_0000;

/// The frames that a host got: each one's ether type and bytes.
type Frames = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;

type Wire = Arc<Mutex<VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>>>;

/// A host: its wire address, the shared wire, its state and the frames it got.
struct Mem {
    at: SocketAddr,
    wire: Wire,
    planet: Option<Vec<u8>>,
    identity: Arc<Mutex<Option<Vec<u8>>>>,
    public: Arc<Mutex<Option<String>>>,
    frames: Frames,
}

impl Host for Mem {
    fn wire(&mut self, to: SocketAddr, packet: &[u8]) {
        self.wire.lock().unwrap().push_back((self.at, to, packet.to_vec()));
    }
    fn frame(&mut self, _: u64, _: u64, _: u64, ether_type: u16, data: &[u8]) {
        self.frames.lock().unwrap().push((ether_type, data.to_vec()));
    }
    fn put(&mut self, kind: i32, data: Option<&[u8]>) {
        match kind {
            state::IDENTITY_SECRET => *self.identity.lock().unwrap() = data.map(<[u8]>::to_vec),
            state::IDENTITY_PUBLIC => {
                *self.public.lock().unwrap() = data.map(|d| String::from_utf8_lossy(d).trim().to_string())
            }
            _ => {}
        }
    }
    fn get(&mut self, kind: i32) -> Option<Vec<u8>> {
        match kind {
            state::PLANET => self.planet.clone(),
            state::IDENTITY_SECRET => self.identity.lock().unwrap().clone(),
            _ => None,
        }
    }
}

struct Peer {
    node: Node,
    at: SocketAddr,
    frames: Frames,
    public: Arc<Mutex<Option<String>>>,
}

type Kept = Arc<Mutex<Option<Vec<u8>>>>;

fn peer(at: &str, wire: &Wire, planet: Option<Vec<u8>>, identity: Kept, now: i64) -> Peer {
    let at: SocketAddr = at.parse().unwrap();
    let (frames, public) = (Arc::default(), Arc::default());
    let mem =
        Mem { at, wire: wire.clone(), planet, identity, public: Arc::clone(&public), frames: Arc::clone(&frames) };
    Peer { node: Node::new(Box::new(mem), now).expect("a node"), at, frames, public }
}

/// Deliver each packet on the wire, and run the timers, until `until`.
fn run(peers: &mut [&mut Peer], wire: &Wire, now: &mut i64, until: i64) {
    while *now < until {
        loop {
            let next = wire.lock().unwrap().pop_front();
            let Some((from, to, packet)) = next else { break };
            if let Some(p) = peers.iter_mut().find(|p| p.at == to) {
                p.node.wire(*now, from, &packet).unwrap();
            }
        }
        for p in peers.iter_mut() {
            p.node.background(*now).unwrap();
        }
        *now += 50;
    }
}

/// An IPv6 UDP frame from `from` to `to`, to port 4242, with `payload`.
fn udp6(from: [u8; 16], to: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[17, 64]);
    out.extend_from_slice(&from);
    out.extend_from_slice(&to);
    out.extend_from_slice(&[0x10, 0x92, 0x10, 0x92]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

/// The 6plane address of `address` on `nwid` (`InetAddress::makeIpv66plane`).
fn sixplane(nwid: u64, address: u64) -> [u8; 16] {
    let n = (nwid ^ (nwid >> 32)) as u32;
    let mut out = [0u8; 16];
    out[0] = 0xfc;
    out[1..5].copy_from_slice(&n.to_be_bytes());
    out[5..10].copy_from_slice(&address.to_be_bytes()[3..8]);
    out[15] = 1;
    out
}

#[test]
fn two_members_of_an_ad_hoc_network_exchange_a_frame_through_a_root_of_the_test() {
    let wire: Wire = Arc::default();
    let mut now = 1_800_000_000_000;
    // The root's identity first, then a planet of it, which the root reads too.
    let kept: Kept = Arc::default();
    let first = peer("10.0.0.1:9993", &wire, None, kept.clone(), now);
    let identity = first.public.lock().unwrap().clone().expect("the root's public identity");
    drop(first);
    let planet = crate::world(149_604_618, 1_800_000_000_000, &[(identity.as_str(), "10.0.0.1/9993")]).unwrap();
    let mut root = peer("10.0.0.1:9993", &wire, Some(planet.clone()), kept, now);
    let mut a = peer("10.0.0.2:9993", &wire, Some(planet.clone()), Arc::default(), now);
    let mut b = peer("10.0.0.3:9993", &wire, Some(planet), Arc::default(), now);
    a.node.join(NWID).unwrap();
    b.node.join(NWID).unwrap();
    run(&mut [&mut root, &mut a, &mut b], &wire, &mut now, 1_800_000_010_000);
    let (from, to) = (sixplane(NWID, a.node.address()), sixplane(NWID, b.node.address()));
    let frame = udp6(from, to, b"podssh over zerotier");
    let (source, dest) = (a.node.mac(NWID), b.node.mac(NWID));
    a.node.frame(now, NWID, source, dest, 0x86dd, &frame).unwrap();
    run(&mut [&mut root, &mut a, &mut b], &wire, &mut now, 1_800_000_020_000);
    let got = b.frames.lock().unwrap().clone();
    assert!(got.iter().any(|(t, data)| *t == 0x86dd && data == &frame), "b got {} frames", got.len());
}
