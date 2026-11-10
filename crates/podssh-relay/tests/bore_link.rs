//! The bore road (T-569) through a stand-in of bore's server on the loopback
//! (`bore_stand_in`, from bore's source): a node registers at the first port
//! of its key, and a client that derives the same ports from the node's key
//! carries 1 MiB each way under the resumable layer and the end-to-end
//! channel, to an echo behind the node; two visitors one after the other
//! each come on a new connection with `Accept`, and nothing goes on the
//! control connection after `Hello`; a server that restarts makes the node
//! register again, and the session goes on; a port that another tunnel
//! holds sends the node and the client to the next of the series; a server
//! with a secret takes its answer and refuses none or another; a stranger
//! with the node's ports and hello is refused by the end-to-end channel; a
//! client gives up when no port gives the hello. Planted
//! (`scripts/plants/t569-accept-on-control.patch`): the `Accept` sent on the
//! control connection, and the test of the second visitor fails.

#![cfg(feature = "bore")]

mod bore_stand_in;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bore_stand_in::StandIn;
use podssh_relay::bore::{self, ports, Dialer, Node, Secret, Service};
use podssh_relay::e2e::ends;
use podssh_relay::identity::Identity;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::Settings;
use podssh_ws::ProxyChoice;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(120);
const BUDGET: usize = 64 << 20;
const PIPE: usize = 256 * 1024;
/// The stand-in's heartbeat, faster than bore's 500 ms.
const TICK: Duration = Duration::from_millis(100);

fn say(who: &'static str) -> bore::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

fn identity(seed: u8) -> Arc<Identity> {
    Arc::new(Identity::from_seed(&[seed; 32]))
}

fn fingerprint(seed: u8) -> String {
    identity(seed).public().fingerprint()
}

/// The stand-in, in bore's default range.
async fn stand_in(secret: Option<&str>) -> StandIn {
    StandIn::start(secret, ports::LOW..=ports::HIGH, TICK).await
}

fn service_of(stand_in: &StandIn, secret: Option<&str>) -> Service {
    Service { host: "127.0.0.1".into(), port: stand_in.port, secret: secret.map(Secret::new) }
}

/// A node at `service` with the ports and the hello of the key of
/// `seen_as`; its channel's key is the one that [`serve`] gives it, so a
/// stranger can take another's ports.
fn node_of(service: &Service, seen_as: u8) -> Node {
    Node::of_key(service.clone(), &fingerprint(seen_as), bore::tcp(ProxyChoice::Direct), say("node"))
}

fn dialer(service: &Service, seed: u8) -> Dialer {
    let dialer = Dialer::new(service.clone(), &fingerprint(seed), bore::tcp(ProxyChoice::Direct), say("client"));
    dialer.with_wait(Duration::from_secs(3))
}

/// An echo behind the end-to-end channel of the node of `key`, counted
/// each time a session reaches it.
fn open_echo(
    key: u8,
    opened: Arc<AtomicUsize>,
) -> impl Fn() -> std::future::Ready<Result<DuplexStream, String>> + Clone {
    let node = ends::Node::open_to_all(identity(key), Arc::new(|line: String| eprintln!("node's channel: {line}")));
    move || {
        let (node, opened) = (node.clone(), opened.clone());
        let (ours, theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let echo = || async move {
                opened.fetch_add(1, Ordering::SeqCst);
                let (echo, mut far) = tokio::io::duplex(PIPE);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(&mut far);
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
                Ok::<_, String>(echo)
            };
            ends::serve_node(theirs, &node, echo).await;
        });
        std::future::ready(Ok(ours))
    }
}

/// Serve `node` with the echo of `key` until the test ends.
async fn serve(node: Node, key: u8, opened: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let first = node.register().await.expect("the node registers");
    eprintln!("{}", node.line(&first));
    tokio::spawn(bore::far::serve_kept(node, Some(first), settings, BUDGET, open_echo(key, opened), keeper))
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

/// A session of the client to the node of `key`, under the channel: `out`
/// goes up in two halves, with `between` run after the first came back, and
/// the echo must give each byte back once, in order.
async fn session<B: std::future::Future<Output = ()>>(dialer: &Dialer, key: u8, out: Vec<u8>, between: B) {
    let (app, user) = tokio::io::duplex(PIPE);
    let node_key = identity(key).public();
    let (cipher, channel) = ends::operator(app, identity(1), move |seen| {
        (seen == &node_key).then_some(()).ok_or_else(|| "not the node".to_string())
    });
    let channel = tokio::spawn(channel);
    let carrying = Box::pin(bore::carry(dialer, cipher, Settings::default(), |_| {}));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let half = out.len() / 2;
        let mut back = vec![0u8; out.len()];
        writer.write_all(&out[..half]).await.expect("the layer takes the bytes");
        reader.read_exact(&mut back[..half]).await.expect("the first half back");
        between.await;
        writer.write_all(&out[half..]).await.expect("the layer takes the rest");
        reader.read_exact(&mut back[half..]).await.expect("the rest back");
        back
    };
    let both = async {
        tokio::select! {
            back = using => back,
            ended = carrying => panic!("the session ended first: {:?}", ended.map(|_| ())),
        }
    };
    let back = tokio::time::timeout(LIMIT, both).await.expect("the session in time");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&out), "each byte came back once, in order");
    channel.abort();
}

// Each test serves a node key of its own: the stand-in binds the ports that
// a key gives on this machine's loopback, and the tests run at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_registers_at_a_port_of_its_key_and_a_session_carries_one_mib_each_way_under_the_channel() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    let node = node_of(&service, 2);
    let series = node.ports.clone();
    assert_eq!(series, ports::of_fingerprint(&fingerprint(2)), "the node's key gives its ports");
    let opened = Arc::new(AtomicUsize::new(0));
    let serving = serve(node, 2, opened.clone()).await;
    let given: Vec<u16> = stand_in.hellos().iter().filter(|(_, given)| *given).map(|(port, _)| *port).collect();
    assert_eq!(given.len(), 1, "one registration: {:?}", stand_in.hellos());
    assert!(series.contains(&given[0]), "a port of the key's series: {given:?} of {series:?}");
    let client = dialer(&service, 2);
    assert_eq!(client.ports(), &series[..], "the client derives the same ports from the node's key");
    session(&client, 2, bytes(2 * MIB, 1), async {}).await;
    assert_eq!(opened.load(Ordering::SeqCst), 1, "one session reached the target, after the channel");
    assert!(stand_in.seen.accepts.load(Ordering::SeqCst) >= 1);
    serving.abort();
}

/// The test of a second visitor (T-569's Prove): each comes on a new
/// connection with `Accept`; the planted defect sends `Accept` on the
/// control connection, which bore's server never reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_visitors_one_after_the_other_each_come_on_a_new_connection_with_accept() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    let opened = Arc::new(AtomicUsize::new(0));
    let serving = serve(node_of(&service, 12), 12, opened.clone()).await;
    for seed in [3, 4] {
        session(&dialer(&service, 12), 12, bytes(MIB, seed), async {}).await;
    }
    assert_eq!(opened.load(Ordering::SeqCst), 2, "two sessions");
    assert!(stand_in.seen.accepts.load(Ordering::SeqCst) >= 2, "each visitor taken by Accept");
    assert_eq!(stand_in.seen.stray.load(Ordering::SeqCst), 0, "nothing on the control connection after Hello");
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_restarts_makes_the_node_register_again_and_the_session_goes_on() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    let opened = Arc::new(AtomicUsize::new(0));
    let serving = serve(node_of(&service, 22), 22, opened.clone()).await;
    let restarted = async {
        stand_in.restart();
        // The node's next registration, at its key's port again.
        let deadline = tokio::time::Instant::now() + LIMIT;
        while stand_in.hellos().iter().filter(|(_, given)| *given).count() < 2 {
            assert!(tokio::time::Instant::now() < deadline, "no registration again: {:?}", stand_in.hellos());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    session(&dialer(&service, 22), 22, bytes(MIB, 5), restarted).await;
    let given: Vec<u16> = stand_in.hellos().iter().filter(|(_, given)| *given).map(|(port, _)| *port).collect();
    assert_eq!(given[0], given[1], "the same port of the key, once the restart freed it");
    assert_eq!(opened.load(Ordering::SeqCst), 1, "the layer moved the one session; the target opened once");
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_that_another_tunnel_holds_sends_the_node_and_the_client_to_the_next() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    let series = ports::of_fingerprint(&fingerprint(32));
    // Another tunnel's service at the first port; where the machine holds
    // the port already, the server cannot give it either.
    let _squat = bore_stand_in::squat(series[0]).await;
    let opened = Arc::new(AtomicUsize::new(0));
    let serving = serve(node_of(&service, 32), 32, opened.clone()).await;
    let hellos = stand_in.hellos();
    assert_eq!(hellos.first(), Some(&(series[0], false)), "the first port refused: {hellos:?}");
    assert!(hellos.iter().any(|(port, given)| *given && series[1..].contains(port)), "{hellos:?}");
    session(&dialer(&service, 32), 32, bytes(MIB, 6), async {}).await;
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_with_a_secret_takes_its_answer_and_refuses_none_or_another() {
    let stand_in = stand_in(Some("s3cret")).await;
    let none = node_of(&service_of(&stand_in, None), 42).register().await.expect_err("no secret");
    assert!(none.contains("asks a secret"), "{none}");
    let wrong = node_of(&service_of(&stand_in, Some("another")), 42).register().await.expect_err("another secret");
    assert!(wrong.contains("invalid secret"), "{wrong}");
    assert!(!wrong.contains("another") && !none.contains("s3cret"), "a secret is never said");
    let service = service_of(&stand_in, Some("s3cret"));
    let opened = Arc::new(AtomicUsize::new(0));
    let serving = serve(node_of(&service, 42), 42, opened.clone()).await;
    session(&dialer(&service, 42), 42, bytes(MIB, 7), async {}).await;
    serving.abort();
}

/// A stranger that holds the node's ports and says its hello, both public:
/// the client's end-to-end channel refuses its key, and its target never
/// opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_with_the_node_s_ports_and_hello_is_refused_by_the_end_to_end_channel() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    let opened = Arc::new(AtomicUsize::new(0));
    // The key 53's channel, at the ports and with the hello of the key 52.
    let serving = serve(node_of(&service, 52), 53, opened.clone()).await;
    let (app, _user) = tokio::io::duplex(PIPE);
    let node_key = identity(52).public();
    let (cipher, channel) = ends::operator(app, identity(1), move |seen| {
        (seen == &node_key).then_some(()).ok_or_else(|| "not the node".to_string())
    });
    let client = dialer(&service, 52);
    let carrying = tokio::spawn(async move { bore::carry(&client, cipher, Settings::default(), |_| {}).await });
    let refused = tokio::time::timeout(LIMIT, channel).await.expect("the channel ends in time");
    assert!(refused.is_err(), "the channel let a stranger in");
    assert_eq!(opened.load(Ordering::SeqCst), 0, "the stranger's target never opened");
    carrying.abort();
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_gives_up_when_no_port_of_the_key_gives_the_hello() {
    let stand_in = stand_in(None).await;
    let service = service_of(&stand_in, None);
    // The link's stream is no Debug, so `expect_err` cannot name it.
    let Err(why) = dialer(&service, 62).with_wait(Duration::from_millis(500)).link().await else {
        panic!("a link with no node");
    };
    assert!(why.contains("no port of the node's key") && why.contains("gave its hello"), "{why}");
}
