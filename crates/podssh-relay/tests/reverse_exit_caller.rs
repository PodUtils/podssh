//! The callers of a node's exit (T-721), with no relay and no Cloudflare
//! account: a stand-in caller (a Worker's part, the end-to-end channel with
//! its own key) opens the node's channel straight over a pipe. The node is
//! `podssh node --exit` as its roads serve it: `exit_caller::serve` around
//! the channel, `pod-relay`'s routes, the door of grants with the exit's
//! beside it, and a dial that stands for the binary's (`node_exit`, whose
//! own tests hold each name's addresses) with the role's checks:
//!
//! - a member of the net's allowlist reaches a target inside the exit's
//!   range, and its connect and its bytes are counted for its key;
//! - port 25 is refused in the role's words, never dialled, and counted as
//!   a refusal;
//! - a caller that no allowlist names, with a grant of the exit
//!   (`node:FP/+exit`), comes in; the range is for members, so its target
//!   on the loopback is refused in the role's words and never dialled;
//! - a grant of a route does not open the exit.
//!
//! Plants: skip the deny check (`exit_caller::outside` lets each address
//! through): the grant's caller reaches the loopback, and the third test
//! fails; count a refused connect as a success: the second test fails.

#![cfg(all(feature = "pair", feature = "serve", feature = "grant"))]

mod e2e_harness;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use e2e_harness::{identity, node as e2e_node, LIMIT, PIPE};
use podssh_relay::e2e::ends::{self, Node};
use podssh_relay::e2e::{exit_word, Ask, Error, Refusal};
use podssh_relay::grant::{self, Door, Mint, Spent};
use podssh_relay::identity::{Identity, PublicKey};
use podssh_relay::reverse::exit_caller;
use podssh_relay::reverse::exit_count::Counts;
use podssh_relay::reverse::routes::{ExitDial, Grant, Routes};
use podssh_relay::serve::ranges::Range;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The node, a member of its net, and a caller that the net does not name.
const NODE: u8 = 2;
const MEMBER: u8 = 3;
const STRANGER: u8 = 4;

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
            // What the caller sent is read to its end before the close: a
            // socket closed with bytes unread resets the connection, which the
            // exit reads as a cut (the gate's macOS at `aae18e8`).
            let mut sent = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut sent)).await;
        }
    });
    (port, count)
}

/// The exit's dial as `node_exit` makes it, for a literal address: the
/// role's port check first, then each address by the role's check, inside
/// the exit's ranges for a member and none for a caller of a grant.
fn exit_dial(ranges: Vec<Range>) -> Arc<ExitDial> {
    Arc::new(move |_peer: PublicKey, host: String, port: u16| {
        let ranges = ranges.clone();
        Box::pin(async move {
            if let Some(why) = exit_caller::denied_port(&host, port) {
                return Err(Refusal::Other(why));
            }
            let ip: IpAddr = host.parse().map_err(|_| Refusal::NoTarget(format!("{host}: a literal in this test")))?;
            let found = vec![SocketAddr::new(ip, port)];
            let lent = if ends::granted() { Vec::new() } else { ranges };
            if exit_caller::outside(&found, &lent).is_some() {
                return Err(Refusal::Other(exit_caller::not_dialed(&host, port)));
            }
            tokio::net::TcpStream::connect(found[0]).await.map_err(|e| Refusal::NoTarget(e.to_string()))
        })
    })
}

/// A directory of the record of each grant used, made for one test.
fn spent_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    std::env::temp_dir().join(format!("podssh-exit-caller-{tag}-{}-{nanos}", std::process::id()))
}

/// The node: its net's allowlist names the member alone; its grants are
/// the node's own, with the exit's door beside the door of its routes.
fn exit_node(tag: &str) -> Node {
    let member = identity(MEMBER).public();
    let (mut node, _lines) = e2e_node(identity(NODE), move |key: &PublicKey| match *key == member {
        true => Ok(()),
        false => Err("not a member of the net".into()),
    });
    let none: Arc<grant::Issuers> =
        Arc::new(|_: &PublicKey, _: &Ask| -> Result<(), String> { Err("no other issuer in this test".into()) });
    let door = Door { node: identity(NODE).public(), issuers: none, spent: Spent::at(spent_dir(tag)), revoked: None };
    let exit = door.clone();
    node.redeem = Some(Arc::new(move |peer: &PublicKey, ask: &Ask, blob: &[u8]| {
        ends::Redemption::grant(exit_caller::redeem(&door, Some(&exit), peer, ask, blob, now()).map(|r| r.to_string()))
    }));
    node
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A grant for `to` of the node's `route` (`+exit` for its exit), signed by
/// the node's key, used once within an hour.
fn grant_of(to: &Identity, route: &str, serial: u64) -> Vec<u8> {
    let principals = vec![grant::principal(&identity(NODE).public(), Some(route))];
    let once: &[(&str, &[u8])] = &[(grant::ONCE, &[])];
    let mint = Mint {
        nonce: [serial as u8; 32],
        key: to.public(),
        serial,
        key_id: "test grant",
        principals: &principals,
        valid_after: now() - 60,
        valid_before: now() + 3600,
        critical: once,
    };
    mint.sign(&identity(NODE)).blob()
}

/// The routes of an exit with no target of its own, lending `ranges`.
fn routes(ranges: Vec<Range>) -> Routes {
    let grant: Arc<Grant> =
        Arc::new(|_: &PublicKey, _: &str| -> Result<(), String> { Err("no route in this test".into()) });
    Routes {
        dialer: podssh_relay::reverse::tcp::dialer(),
        routes: Arc::new(Vec::new()),
        grant,
        timeout: LIMIT,
        sshd: false,
        exit: Some(exit_dial(ranges)),
        shared: None,
    }
}

/// One session of `caller` to `host:port` through the exit (or to the
/// route `word` when it names one), with `grant`: what it read, or why the
/// channel ended.
async fn through(
    node: Node,
    counts: Arc<Counts>,
    ranges: Vec<Range>,
    caller: Arc<Identity>,
    word: String,
    grant: Option<Vec<u8>>,
) -> Result<String, Error> {
    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, channel) = ends::operator_granted(app_end, caller, |_| Ok(()), Some(word), grant);
    let routes = routes(ranges);
    let node_task = tokio::spawn(async move {
        let open = move |key: PublicKey, ask: Ask| async move { routes.open(&key, &ask).await };
        exit_caller::serve(cipher, &node, counts, open).await
    });
    let channel = tokio::spawn(channel);
    let (mut r, mut w) = tokio::io::split(app);
    let _ = w.write_all(b"hello through the exit").await;
    let _ = w.shutdown().await;
    let mut read = String::new();
    let _ = tokio::time::timeout(LIMIT, r.read_to_string(&mut read)).await;
    let ended = tokio::time::timeout(LIMIT, channel).await.expect("the channel's end in time").unwrap();
    let _ = tokio::time::timeout(LIMIT, node_task).await;
    ended.map(|_| read)
}

fn lent() -> Vec<Range> {
    vec![Range::parse("127.0.0.1").unwrap()]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_allowlist_a_member_reaches_the_range_and_is_counted() {
    let (port, count) = service("inside the range").await;
    let counts = Arc::new(Counts::default());
    let word = exit_word("127.0.0.1", port);
    let read = through(exit_node("member"), counts.clone(), lent(), identity(MEMBER), word, None).await;
    assert_eq!(read.expect("the exit reached its target"), "inside the range");
    assert_eq!(count.load(Ordering::SeqCst), 1, "one dial of the target");
    let rows = counts.rows();
    let row = rows.iter().find(|r| r.key == identity(MEMBER).public().fingerprint()).expect("the member's row");
    assert_eq!((row.connects, row.refusals), (1, 0), "{rows:?}");
    assert!(row.bytes_up > 0 && row.bytes_down > "inside the range".len() as u64, "{rows:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denies_port_25_in_the_role_s_words_and_counters_count_a_refusal() {
    let counts = Arc::new(Counts::default());
    let word = exit_word("127.0.0.1", 25);
    match through(exit_node("port25"), counts.clone(), lent(), identity(MEMBER), word, None).await {
        Err(Error::Refused(Refusal::Other(why))) => {
            assert_eq!(why, "127.0.0.1:25 not in the ALLOW list: port 25 is refused")
        }
        other => panic!("{other:?}"),
    }
    let rows = counts.rows();
    let row = rows.iter().find(|r| r.key == identity(MEMBER).public().fingerprint()).expect("the member's row");
    assert_eq!((row.connects, row.refusals), (0, 1), "a refusal, never a connect: {rows:?}");
    assert_eq!(row.bytes_down, 0, "no session's bytes for a refusal: {rows:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denies_a_grant_s_caller_the_range_of_members_and_never_dials_it() {
    let (port, count) = service("never").await;
    let counts = Arc::new(Counts::default());
    let stranger = identity(STRANGER);
    let grant = grant_of(&stranger, exit_caller::GRANT_ROUTE, 7);
    let word = exit_word("127.0.0.1", port);
    match through(exit_node("grant"), counts.clone(), lent(), stranger.clone(), word, Some(grant)).await {
        Err(Error::Refused(Refusal::Other(why))) => {
            assert_eq!(why, format!("127.0.0.1:{port} not in the ALLOW list: this relay dials no address of it"))
        }
        other => panic!("the grant's caller reached a private address: {other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 0, "the private target was not dialled");
    let rows = counts.rows();
    let row = rows.iter().find(|r| r.key == stranger.public().fingerprint()).expect("the caller's row");
    assert_eq!((row.connects, row.refusals), (0, 1), "{rows:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_allowlist_has_no_stranger_and_a_route_s_grant_opens_no_exit() {
    let (port, count) = service("never").await;
    let stranger = identity(STRANGER);
    let word = exit_word("127.0.0.1", port);
    // No grant: the allowlist does not name it.
    let counts = Arc::new(Counts::default());
    match through(exit_node("none"), counts.clone(), lent(), stranger.clone(), word.clone(), None).await {
        Err(Error::Refused(Refusal::NotAllowed)) => {}
        other => panic!("{other:?}"),
    }
    // A grant of a route of the node, not of its exit.
    let grant = grant_of(&stranger, "web", 8);
    match through(exit_node("route"), counts.clone(), lent(), stranger, word, Some(grant)).await {
        Err(Error::Refused(_)) => {}
        other => panic!("a route's grant opened the exit: {other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 0, "nothing was dialled");
    assert!(counts.rows().is_empty(), "the exit never saw them: {:?}", counts.rows());
}
