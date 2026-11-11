//! ZeroTier's road through ZeroTier Inc.'s own roots and TCP relay (T-733,
//! Q78, a short run of Q91), from GitHub Actions alone
//! (`.github/workflows/zerotier-live.yml`), ignored elsewhere. Two members
//! of this process, each with an identity made for the run and dropped,
//! each on its own TCP connection to the relay of `pod-services`
//! (`zerotier-tcp-relay`), the roots of the core's own planet; both join an
//! ad-hoc network of one port, and a TCP connection between them carries
//! 64 KiB each way. With `PODSSH_ZT_LIVE_PLANT=other`, the second member
//! joins another network, and the run must fail.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_zerotier::member::{sixplane, Member, State};
use podssh_zerotier::relay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The ad-hoc network of the port 4096 alone: `ff`, 0x1000 to 0x1000, `000000`.
const NWID: u64 = 0xff10_0010_0000_0000;
const OTHER: u64 = 0xff10_0110_0100_0000;

/// The relay that `pod-services` names.
fn relay_at() -> SocketAddr {
    let service = pod_services::get("zerotier-tcp-relay").expect("pod-services names zerotier-tcp-relay");
    let endpoint = service.endpoint("tcp").expect("its endpoint tcp");
    SocketAddr::new(endpoint.host().parse().expect("an IP literal"), endpoint.port())
}

async fn member(network: u64) -> Member {
    let tcp = tokio::net::TcpStream::connect(relay_at()).await.expect("the relay takes TCP");
    let wire = relay::carry(tcp, podssh_zerotier::version());
    Member::start(Arc::new(Mutex::new(State::default())), wire, Some(network)).expect("a member")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a live run through ZeroTier's roots and relay: zerotier-live.yml"]
async fn two_members_meet_through_zerotier_s_roots_and_relay_and_carry_64_kib() {
    let planted = std::env::var("PODSSH_ZT_LIVE_PLANT").ok().as_deref() == Some("other");
    let a = member(NWID).await;
    let b = member(if planted { OTHER } else { NWID }).await;
    let at = SocketAddr::new(IpAddr::V6(sixplane(NWID, b.address)), 4096);
    if !planted {
        let mut listener = b.stack.as_ref().unwrap().listen(at).unwrap();
        tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
    }
    let stack = a.stack.as_ref().unwrap();
    let began = std::time::Instant::now();
    let mut conn = stack.connect(at, Duration::from_secs(90)).await.expect("a connection through the relay");
    let sent: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    conn.write_all(&sent).await.unwrap();
    let mut got = vec![0u8; 65536];
    tokio::time::timeout(Duration::from_secs(120), conn.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(got, sent);
    eprintln!("64 KiB each way through ZeroTier's relay in {:.1} s", began.elapsed().as_secs_f64());
}
