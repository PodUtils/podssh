//! croc's relay road (T-694) against croc's own relay and croc-web's
//! bridge, of a pinned release, on the loopback of a runner
//! (`.github/workflows/croc-interop.yml`): the cases of `croc.rs`, whose
//! stand-in is written from croc's source, against the software itself.
//! `PODSSH_CROC_INTEROP_BRIDGE` names croc-web's `/ws`, behind which four
//! relay hosts lead to one `croc relay`; each test is ignored unless asked,
//! as it needs them. The relay's frame to a waiting member is croc's own
//! (1 s), and the counts that the stand-in keeps are not asked of croc.

#![cfg(feature = "croc")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::croc::meet::{meet, Missed};
use podssh_relay::croc::{client, far, Bridge, Dialer, Node, Rooms};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{OsEntropy, Settings};
use podssh_relay::transit::{Link, Part};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(120);
const BUDGET: usize = 64 << 20;
const NAME: &str = "0123456789abcdef0123456789abcdef";
/// croc's relay sends a waiting member a frame each second.
const TICK: Duration = Duration::from_secs(1);

fn say(who: &'static str) -> podssh_relay::croc::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// The words of a pair of this run's.
fn rooms() -> Rooms {
    let mut seed = [0u8; 8];
    podssh_relay::session::Entropy::fill(&mut OsEntropy, &mut seed).unwrap();
    Rooms::of_pair(NAME, &format!("connect-token-of-the-test-{seed:?}"))
}

/// croc-web's bridge of the workflow, before four relay hosts, with
/// croc's own password.
async fn stand_in() -> ((), (), Bridge) {
    let url = std::env::var("PODSSH_CROC_INTEROP_BRIDGE").expect("PODSSH_CROC_INTEROP_BRIDGE: croc-web's /ws");
    let url = WsUrl::parse(&url).expect("a WebSocket URL");
    ((), (), Bridge { relays: 4, public: false, ..Bridge::named(url) })
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
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn two_ends_meet_through_the_bridge_and_carry_one_mib_each_way() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    let client = dialer(&bridge, &rooms);
    let run = async {
        let (served, link) = tokio::join!(node_meets(&bridge, &rooms, 0, LIMIT), client.link());
        one_mib_each_way(served.expect("the node met"), link.expect("the client met")).await;
    };
    tokio::time::timeout(LIMIT, run).await.expect("in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn a_node_that_waited_through_the_relay_s_frames_still_meets() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    let client = dialer(&bridge, &rooms);
    let late_client = async {
        // Three of the relay's frames go to the node first.
        tokio::time::sleep(TICK * 3).await;
        client.link().await
    };
    let (served, link) = tokio::join!(node_meets(&bridge, &rooms, 0, LIMIT), late_client);
    tokio::time::timeout(LIMIT, one_mib_each_way(served.unwrap(), link.unwrap())).await.expect("in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn a_taken_room_sends_the_node_and_the_client_to_the_next() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    // Two strangers who know the rooms hold room 0, piped to each other.
    let strangers = Rooms::knowing_only(rooms.base());
    let hold = |part: Part| {
        let (bridge, strangers) = (bridge.clone(), strangers.clone());
        async move {
            let session = far::dial(&bridge.url(&strangers), &Trust::Default, &ProxyChoice::Direct).await.unwrap();
            let met = meet(&session, &bridge.password, &strangers, 0, part, Some(LIMIT), &mut OsEntropy).await;
            (session, met)
        }
    };
    let ((_one, one), (_two, two)) = tokio::join!(hold(Part::Node), hold(Part::Client));
    assert!(one.is_ok() && two.is_ok(), "the strangers met: {one:?} {two:?}");
    let busy = async {
        let session = far::dial(&bridge.url(&rooms), &Trust::Default, &ProxyChoice::Direct).await.unwrap();
        meet(&session, &bridge.password, &rooms, 0, Part::Node, Some(LIMIT), &mut OsEntropy).await
    };
    assert_eq!(busy.await.err(), Some(Missed::Full));
    let client = dialer(&bridge, &rooms);
    let (served, link) = tokio::join!(node_meets(&bridge, &rooms, 1, LIMIT), client.link());
    tokio::time::timeout(LIMIT, one_mib_each_way(served.unwrap(), link.unwrap())).await.expect("in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn a_client_gives_up_on_a_node_that_is_not_there_within_its_wait() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let client = dialer(&bridge, &rooms()).with_waits(Duration::from_secs(6), Duration::from_millis(500));
    let started = tokio::time::Instant::now();
    let why = client.link().await.expect_err("no node");
    assert!(why.contains("no node met this client") && why.contains("with no one"), "{why}");
    assert!(started.elapsed() < Duration::from_secs(6), "four empty rooms take four short waits");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn a_peer_that_knows_the_rooms_alone_is_refused_by_the_node() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    let stranger = Rooms::knowing_only(rooms.base());
    let posing = async {
        let session = far::dial(&bridge.url(&stranger), &Trust::Default, &ProxyChoice::Direct).await.unwrap();
        meet(&session, &bridge.password, &stranger, 0, Part::Client, Some(LIMIT), &mut OsEntropy).await
    };
    let (node, stranger) = tokio::join!(node_meets(&bridge, &rooms, 0, LIMIT), posing);
    assert!(matches!(node, Err(Missed::NotProven(_))), "the node let a stranger in: {:?}", node.err());
    assert!(matches!(stranger, Err(Missed::NotProven(_))), "{stranger:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn two_clients_of_one_pair_never_take_each_other_for_the_node() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    let waits = (Duration::from_secs(6), Duration::from_secs(1));
    let (one, two) = (dialer(&bridge, &rooms).with_waits(waits.0, waits.1), dialer(&bridge, &rooms));
    let two = two.with_waits(waits.0, waits.1);
    let (first, second) = tokio::join!(one.link(), two.link());
    let (first, second) = (first.expect_err("a client met a client"), second.expect_err("a client met a client"));
    assert!(first.contains("no node met") && second.contains("no node met"), "{first}; {second}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn another_password_is_refused_with_croc_s_words() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let wrong = Bridge { password: "not croc's".into(), ..bridge.clone() };
    let why = dialer(&wrong, &rooms()).link().await.expect_err("a wrong password");
    assert!(why.contains("bad password"), "{why}");
}

/// An echo of each byte, as a node's target.
async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "croc's relay and croc-web: croc-interop.yml"]
async fn a_session_of_the_layer_through_a_node_echoes_one_mib() {
    let (_relay, _bridge, bridge) = stand_in().await;
    let rooms = rooms();
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let words = rooms.clone();
    let node = Node {
        bridge: bridge.clone(),
        rooms: Arc::new(move || words.clone()),
        trust: Trust::Default,
        proxy: ProxyChoice::Direct,
        say: say("node"),
    };
    let serving = tokio::spawn(far::serve_kept(node, settings, BUDGET, echo, keeper));
    let client = dialer(&bridge, &rooms);
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.expect("the layer takes the bytes") };
        let reading = async {
            let (mut back, mut buf) = (Vec::with_capacity(out.len()), vec![0u8; 64 * 1024]);
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
            }
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        back
    };
    let carrying = Box::pin(client::carry(&client, app, settings, |_| {}));
    let both = async {
        tokio::select! {
            back = using => back,
            ended = carrying => panic!("the session ended first: {:?}", ended.map(|_| ())),
        }
    };
    let back = tokio::time::timeout(LIMIT, both).await.expect("the session in time");
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    serving.abort();
}
