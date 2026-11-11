//! croc's relay road (T-694) through getcroc.com's own bridge and relays,
//! by the operator's rulings Q78 and Q91: one short run, from GitHub Actions
//! (`.github/workflows/croc-live.yml`), never in the gate, so it is ignored
//! unless asked. A node and a client of one pair meet in the pair's first
//! room through `wss://getcroc.com/ws` (pod-services) and carry 1 MiB each
//! way with equal digests. With `PODSSH_CROC_TEST_PLANT=stranger`, the
//! client holds another pair's rooms, and no node may meet it: the check is
//! not vacuous.

#![cfg(feature = "croc")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::croc::meet::{meet, Missed};
use podssh_relay::croc::{client, far, Bridge, Dialer, Rooms};
use podssh_relay::session::OsEntropy;
use podssh_relay::transit::{Link, Part};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(120);
const NAME: &str = "0123456789abcdef0123456789abcdef";

fn say(who: &'static str) -> podssh_relay::croc::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// The words of a pair of this run's.
fn rooms() -> Rooms {
    let mut seed = [0u8; 8];
    podssh_relay::session::Entropy::fill(&mut OsEntropy, &mut seed).unwrap();
    Rooms::of_pair(NAME, &format!("connect-token-of-the-test-{seed:?}"))
}

/// The bridge of `pod-services`' service `croc`: getcroc.com's.
fn listed() -> Bridge {
    Bridge::listed().expect("pod-services lists the service croc")
}

/// Bytes that a seed fixes (xorshift64*).
fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Write `out` on `link` while as many bytes are read from it: their digest.
async fn both_ways(link: Link, out: Vec<u8>) -> Vec<u8> {
    let (mut reader, mut writer) = tokio::io::split(link);
    let want = out.len();
    let writing = async { writer.write_all(&out).await.expect("the link takes the bytes") };
    let reading = async {
        let mut digest = Sha256::new();
        let (mut got, mut buf) = (0, vec![0u8; 64 * 1024]);
        while got < want {
            let n = reader.read(&mut buf[..(want - got).min(64 * 1024)]).await.expect("the link gives the bytes");
            assert!(n > 0, "the link ended after {got} bytes");
            digest.update(&buf[..n]);
            got += n;
        }
        digest.finalize().to_vec()
    };
    let ((), read) = tokio::join!(writing, reading);
    read
}

/// A node's meeting in room `slot`, waiting `wait` for a peer.
async fn node_meets(bridge: &Bridge, rooms: &Rooms, slot: usize, wait: Duration) -> Result<Link, Missed> {
    let session = far::dial(&bridge.url(rooms), &Trust::Default, &ProxyChoice::Direct).await.expect("the bridge");
    let first = meet(&session, &bridge.password, rooms, slot, Part::Node, Some(wait), &mut OsEntropy).await?;
    Ok(Link::start_by(session, first, client::WHO))
}

fn dialer(bridge: &Bridge, rooms: &Rooms) -> Dialer {
    Dialer::new(bridge.clone(), rooms.clone(), Trust::Default, ProxyChoice::Direct, say("client"))
}

async fn one_mib_each_way(served: Link, link: Link) {
    let (up, down) = (bytes(MIB, 1), bytes(MIB, 2));
    let (want_up, want_down) = (Sha256::digest(&up).to_vec(), Sha256::digest(&down).to_vec());
    let (got_down, got_up) = tokio::join!(both_ways(link, up), both_ways(served, down));
    assert_eq!(got_up, want_up, "the node got the client's bytes");
    assert_eq!(got_down, want_down, "the client got the node's bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a live run through getcroc.com: croc-live.yml"]
async fn two_ends_of_a_pair_meet_at_getcroc_com_and_carry_one_mib_each_way() {
    let bridge = listed();
    assert!(bridge.public, "the bridge of pod-services is a third party's");
    let rooms = rooms();
    let planted = std::env::var("PODSSH_CROC_TEST_PLANT").ok().as_deref() == Some("stranger");
    let theirs = if planted { self::rooms() } else { rooms.clone() };
    let client = dialer(&bridge, &theirs).with_waits(Duration::from_secs(20), Duration::from_secs(5));
    let run = async {
        let (served, link) = tokio::join!(node_meets(&bridge, &rooms, 0, Duration::from_secs(30)), client.link());
        one_mib_each_way(served.expect("the node met"), link.expect("the client met")).await;
    };
    tokio::time::timeout(LIMIT, run).await.expect("in time");
}
