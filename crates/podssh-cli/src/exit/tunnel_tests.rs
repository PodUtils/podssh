//! The session of an exit behind a quick tunnel (T-459), apart from the
//! edge: the node's handler as `podssh node NAME --exit --quick-tunnel`
//! builds it (the layer, the channel, the routes with the exit's dial and no
//! target of its own), each visitor's link a pipe in memory, as a test
//! listens nowhere but on the loopback for its target. The edge's WebSocket
//! itself is podssh-relay's `tests/quick_exit.rs`, and the live run is
//! `quick-tunnel-live.yml`.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends::Admit;
use podssh_relay::e2e::{exit_word, Ask, Refusal as NodeRefusal};
use podssh_relay::identity::{Identity, PublicKey};
use podssh_relay::reverse::framing::SessionId;
use podssh_relay::reverse::routes::{ExitDial, Grant, Routed, Routes};
use podssh_relay::reverse::{self, Handler, Layered};
use podssh_relay::session::client;
use podssh_relay::session::resume::Next;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

use super::{host_of, judged, through};
use crate::channel::{Expect, Operator};
use crate::layered::Line;

const LIMIT: Duration = Duration::from_secs(20);
const PIPE: usize = 256 * 1024;

/// A TCP service on the loopback that writes `word` and closes; the count
/// of its connections.
async fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes()).await;
        }
    });
    (port, count)
}

/// The exit's dial: the loopback's port `lent` alone, as a range of
/// `--routes` lends it; each other target refused before any dial. The
/// binary's own dial (`crate::node_exit`) has its tests of each address.
fn exit_dial(lent: u16) -> Arc<ExitDial> {
    Arc::new(move |_peer: PublicKey, host: String, port: u16| {
        Box::pin(async move {
            if host != "127.0.0.1" || port != lent {
                return Err(NodeRefusal::Other(format!("{host}:{port} is inside no range of this exit")));
            }
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| NodeRefusal::NoTarget(e.to_string()))
        })
    })
}

/// The node behind the tunnel, and the count of its visitors' links.
struct Node {
    handler: Layered<Routed>,
    ids: AtomicU64,
}

impl Node {
    fn new(lent: u16) -> Arc<Node> {
        let client = Identity::from_seed(&[1; 32]).public();
        let admit: Arc<Admit> =
            Arc::new(move |k: &PublicKey, _: &Ask| if *k == client { Ok(()) } else { Err("unlisted".into()) });
        let channel = crate::channel::node_end("quick", Identity::from_seed(&[2; 32]), admit);
        let grant: Arc<Grant> = Arc::new(|_: &PublicKey, _: &str| Ok(()));
        let routes = Routes {
            dialer: reverse::tcp::dialer(),
            routes: Arc::new(Vec::new()),
            grant,
            timeout: LIMIT,
            sshd: false,
            exit: Some(exit_dial(lent)),
            shared: None,
        };
        let settings = crate::layered::settings().off_the_pair();
        let handler = Layered::new(Routed::new(routes, channel), settings, reverse::layered::NODE_BUDGET);
        Arc::new(Node { handler, ids: AtomicU64::new(1) })
    }

    /// A visitor's link, as the edge brings one.
    async fn link(self: &Arc<Node>) -> DuplexStream {
        let (visitor, theirs) = tokio::io::duplex(64 * 1024);
        let id = SessionId::parse(format!("{:032x}", self.ids.fetch_add(1, Ordering::SeqCst)).as_bytes()).unwrap();
        let mut session = self.handler.open(id).await.unwrap();
        tokio::spawn(async move {
            let mut theirs = theirs;
            let _ = tokio::io::copy_bidirectional(&mut theirs, &mut session).await;
        });
        visitor
    }
}

/// One session to `host:port` through the exit of `node`, as `super::open`
/// carries it: what the client read, and how the session ended.
async fn session(node: &Arc<Node>, host: &str, port: u16) -> (String, crate::layered::Carried) {
    let greeted = client::greeted(node.link().await).await.unwrap();
    assert!(greeted.layer(), "a node's first frame is the layer's GREETING");
    let dial = {
        let node = node.clone();
        move || {
            let node = node.clone();
            async move { Next::Link(node.link().await) }
        }
    };
    let identity = Arc::new(Identity::from_seed(&[1; 32]));
    let expect = Expect::Ticket(Identity::from_seed(&[2; 32]).public());
    let channel = Some(Operator { identity, expect, route: Some(exit_word(host, port)) });
    let (app, mut ours) = tokio::io::duplex(PIPE);
    let say = |_: Line| {};
    let carrying = through(greeted, dial, app, channel, &say, |_| {});
    let reading = async move {
        let _ = ours.shutdown().await;
        let mut read = String::new();
        let _ = ours.read_to_string(&mut read).await;
        read
    };
    let both = tokio::time::timeout(LIMIT, async { tokio::join!(carrying, reading) });
    let (carried, read) = both.await.expect("the session ends in time");
    (read, carried)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_reaches_a_target_inside_the_range_of_the_exit_behind_the_tunnel() {
    let (port, count) = service("inside the range").await;
    let (read, carried) = session(&Node::new(port), "127.0.0.1", port).await;
    assert_eq!(read, "inside the range");
    assert_eq!(judged(&carried), None, "a good end: {:?} {:?}", carried.why, carried.channel);
    assert_eq!(count.load(Ordering::SeqCst), 1, "one dial of the target");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_of_no_range_is_refused_in_the_exit_s_words_and_never_dialled() {
    let (lent, _) = service("lent").await;
    let (other, count) = service("never").await;
    let (read, carried) = session(&Node::new(lent), "127.0.0.1", other).await;
    assert!(read.is_empty(), "nothing of the refused target: {read}");
    let (code, why) = judged(&carried).expect("a refusal");
    assert!(why.contains("inside no range"), "{why}");
    assert_ne!(code, 0);
    assert_eq!(count.load(Ordering::SeqCst), 0, "the refused target was not dialled");
}

#[test]
fn the_exit_s_tunnel_takes_no_user_no_pair_and_no_carrier() {
    assert_eq!(host_of("gw", None, None).unwrap(), None, "a name of the net is no tunnel");
    let host = host_of("cf://Lab-One.trycloudflare.com", None, None).unwrap();
    assert_eq!(host.as_deref(), Some("lab-one.trycloudflare.com"), "the resolver's case");
    for (name, pair, carrier, says) in [
        ("cf://me@lab.example", None, None, "takes no user name"),
        ("cf://lab.example", Some("x"), None, "has no pair"),
        ("cf://lab.example", None, Some("exec:cat"), "--carrier is another road"),
        ("cf://lab.example:443", None, None, "has no port"),
    ] {
        let refusal = host_of(name, pair, carrier).unwrap_err();
        assert!(refusal.code == 64 && refusal.message.contains(says), "{name}: {}", refusal.message);
    }
}
