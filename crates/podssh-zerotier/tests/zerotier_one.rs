//! ZeroTier's road against ZeroTierOne's own `zerotier-one` (T-733), from
//! GitHub Actions alone (`.github/workflows/zerotier-live.yml`, the job
//! `one`), ignored elsewhere: the runner's `zerotier-one`, built from the
//! pinned commit, joins the ad-hoc network of port 4096 through ZeroTier
//! Inc.'s roots; a member of this process joins it through the TCP relay of
//! `pod-services`. Both ways must carry TCP: the member echoes at its 6plane
//! address, which it writes to `PODSSH_ZT_ONE_OUT` for the runner's client;
//! and it connects to the echo that the runner keeps at the 6plane address
//! of `zerotier-one`'s node, `PODSSH_ZT_ONE_NODE`. NDP is the cores' own
//! emulation of 6plane, at each end.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_zerotier::member::{sixplane, Member, State};
use podssh_zerotier::pair::adhoc;
use podssh_zerotier::relay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The port of the network, where each end waits.
const PORT: u16 = 4096;

fn relay_at() -> SocketAddr {
    let service = pod_services::get("zerotier-tcp-relay").expect("pod-services names zerotier-tcp-relay");
    let endpoint = service.endpoint("tcp").expect("its endpoint tcp");
    SocketAddr::new(endpoint.host().parse().expect("an IP literal"), endpoint.port())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a run with the runner's zerotier-one: zerotier-live.yml"]
async fn zerotier_one_and_a_member_carry_tcp_both_ways() {
    let nwid = adhoc(PORT);
    let out = std::env::var("PODSSH_ZT_ONE_OUT").expect("PODSSH_ZT_ONE_OUT");
    let node = std::env::var("PODSSH_ZT_ONE_NODE").expect("PODSSH_ZT_ONE_NODE");
    let node = u64::from_str_radix(node.trim(), 16).expect("zerotier-one's node id, 10 hex digits");
    let tcp = tokio::net::TcpStream::connect(relay_at()).await.expect("the relay takes TCP");
    let wire = relay::carry(tcp, podssh_zerotier::version());
    let member = Member::start(Arc::new(Mutex::new(State::default())), wire, Some(nwid)).expect("a member");
    let stack = member.stack.as_ref().unwrap();
    let mine = SocketAddr::new(IpAddr::V6(sixplane(nwid, member.address)), PORT);

    // zerotier-one's side reaches this member: an echo here.
    let mut listener = stack.listen(mine).unwrap();
    let echo = tokio::spawn(async move {
        let mut conn = listener.accept().await.expect("zerotier-one's host connects");
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        n
    });
    std::fs::write(&out, format!("{}\n", mine.ip())).unwrap();
    eprintln!("the member waits at [{}]:{PORT}", mine.ip());

    // This member reaches zerotier-one's host, whose echo waits at its 6plane address.
    let theirs = SocketAddr::new(IpAddr::V6(sixplane(nwid, node)), PORT);
    let mut conn = podssh_zerotier::road::connect(stack, theirs, Duration::from_secs(120))
        .await
        .expect("a connection to zerotier-one's host");
    conn.write_all(b"podssh to zerotier-one").await.unwrap();
    let mut got = [0u8; 22];
    tokio::time::timeout(Duration::from_secs(60), conn.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(&got, b"podssh to zerotier-one");
    eprintln!("podssh reached zerotier-one's host at {theirs}");

    let n = tokio::time::timeout(Duration::from_secs(180), echo).await.expect("zerotier-one's host came").unwrap();
    assert!(n > 0);
    eprintln!("zerotier-one's host reached podssh at {mine}");
}
