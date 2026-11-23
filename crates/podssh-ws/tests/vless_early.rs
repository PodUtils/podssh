//! TLS 1.3 early data (0-RTT) on podssh's VLESS WebSocket road (T-758): the
//! upgrade request goes to the TLS handshake, a server that took the ticket
//! reads it before its answer, and a server that refuses the ticket gets the
//! same request replayed at 1-RTT on the same connection.
//!
//! The stand-in reads the early data out of its own `ServerConnection` after
//! the handshake and puts those bytes in front of the stream, which is what a
//! server does with 0-RTT. This is the only place a ticket can come from: the
//! store lives in the process, so the first session of a process is 1-RTT.

mod vless_support;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::vless::{self, AtEnd, Dial, Server};
use podssh_ws::vless_early::{self, Opened};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::AsyncReadExt;
use vless_support::{pins, root_file, target, ws_server_early, BANNER, ID, NAME};

const LIMIT: Duration = Duration::from_secs(20);
/// The bytes of the coalesced first write: the padded upgrade request alone,
/// as pod-egress's WebSocket road writes it. VLESS's request follows in the
/// first binary message, as Xray-core's server refuses a frame before the
/// handshake.
const WRITE: usize = 3_333;
/// The size that the link's `ed` names: at least the first write, as the
/// stand-ins reserve that many bytes of early data.
const ED: &str = "4096";

fn server(port: u16) -> Server {
    let query = format!("type=ws&path=%2Fws%3Fed%3D{ED}&security=tls");
    Server::parse(&format!("vless://{ID}@{NAME}:{port}?{query}")).unwrap()
}

fn dial(root: &std::path::Path, nonce: &[u8], window: &Arc<vless::ReplayWindow>) -> Dial {
    Dial {
        trust: Trust::File(root.to_path_buf()),
        way: podssh_ws::client::way(&ProxyChoice::Direct),
        timeout: LIMIT,
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        at_end: AtEnd::Now,
        early: Some(vless::early::Early::new(window.clone(), nonce.to_vec())),
    }
}

/// One session, its version line read, and what its opening did with early
/// data.
async fn session(link: &Server, aim: u16, dial: &Dial) -> (Opened, Vec<u8>) {
    let mut opened = tokio::time::timeout(LIMIT * 3, vless_early::open(link, "127.0.0.1", aim, dial))
        .await
        .expect("within the limit")
        .unwrap_or_else(|e| panic!("{}", e.line("vless", "127.0.0.1:{aim}")));
    let mut banner = vec![0u8; BANNER.len()];
    opened.stream.read_exact(&mut banner).await.unwrap();
    (opened, banner)
}

/// A process's first session has no ticket to resume, so it keeps 1-RTT. The
/// second, with its own nonce, hands the upgrade request to the handshake
/// and the server reads it before its answer. A nonce the window has already
/// seen is refused, opens no early data, and keeps the session at 1-RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ticket_makes_the_second_session_0rtt_and_an_old_nonce_does_not() {
    pins();
    let (root, aim) = (root_file("early-0rtt"), target(true).await);
    let (ws, seen, early) = ws_server_early(ED.parse().unwrap()).await;
    let link = server(ws);
    let window = Arc::new(vless::ReplayWindow::new());

    let (first, banner) = session(&link, aim, &dial(&root, b"a-session-s-own-nonce", &window)).await;
    assert_eq!(banner, BANNER);
    assert_eq!((first.early, first.early_accepted), (vless::early::Offer::OneRtt, Some(false)));
    assert_eq!(first.first_write.bytes, WRITE, "the head alone, padded");

    let (second, banner) = session(&link, aim, &dial(&root, b"the-next-session-s-nonce", &window)).await;
    assert_eq!(banner, BANNER);
    assert_eq!((second.early, second.early_accepted), (vless::early::Offer::ZeroRtt, Some(true)));

    // The `1rtt` word: a nonce that the window has already admitted opens no
    // early data, even where a ticket is stored.
    let taken = b"a-nonce-the-window-saw";
    assert!(matches!(window.admit(taken), vless::Admitted::Fresh));
    let (third, banner) = session(&link, aim, &dial(&root, taken, &window)).await;
    assert_eq!(banner, BANNER);
    assert_eq!((third.early, third.early_accepted), (vless::early::Offer::OneRtt, None));

    let accepted = early.accepted.lock().unwrap().clone();
    assert_eq!(accepted, vec![false, true, false], "the handshake accepted early data on the second session alone");
    let heads = early.bytes.lock().unwrap().clone();
    assert!(heads[0].is_empty(), "no ticket, so the server read no early data: {} bytes", heads[0].len());
    assert_eq!(heads[1].len(), WRITE, "the whole first write arrived before the answer");
    assert!(heads[1].starts_with(b"GET /ws?ed=4096 HTTP/1.1\r\n"), "{:?}", &heads[1][..27]);
    assert!(heads[1].ends_with(b"\r\n\r\n"));
    assert!(heads[2].is_empty(), "a repeat of the nonce sends no early data");

    let requests = seen.requests.lock().unwrap().clone();
    let paths: Vec<&str> = requests.iter().map(|r| r.1.as_str()).collect();
    assert_eq!(paths, vec!["/ws?ed=4096", "/ws?ed=4096", "/ws"]);
    assert_eq!(seen.connections.load(std::sync::atomic::Ordering::SeqCst), 3, "one connection for each session");
    assert_eq!(seen.targets.lock().unwrap().len(), 3);
}

/// A server that cannot decrypt the ticket the client offers refuses the
/// early data. tokio-rustls then replays the same write at 1-RTT on the same
/// connection, so one TCP connection carries the head and the session, and
/// the client says 1-RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_ticket_is_replayed_at_1rtt_on_the_same_connection() {
    pins();
    let (root, aim) = (root_file("early-refused"), target(true).await);
    // The first server issues the ticket; the second has a key of its own and
    // cannot read it, as a server that lost its tickets does.
    let (issuer, _, _) = ws_server_early(ED.parse().unwrap()).await;
    let (refuser, seen, early) = ws_server_early(0).await;
    let window = Arc::new(vless::ReplayWindow::new());

    let (ticket, banner) = session(&server(issuer), aim, &dial(&root, b"issuer-nonce", &window)).await;
    assert_eq!(banner, BANNER);
    assert_eq!((ticket.early, ticket.early_accepted), (vless::early::Offer::OneRtt, Some(false)));

    let (replayed, banner) = session(&server(refuser), aim, &dial(&root, b"refuser-nonce", &window)).await;
    assert_eq!(banner, BANNER, "the session carried after the replay");
    assert_eq!((replayed.early, replayed.early_accepted), (vless::early::Offer::OneRtt, Some(false)));

    assert_eq!(early.accepted.lock().unwrap().clone(), vec![false], "nothing early was accepted");
    assert!(early.bytes.lock().unwrap()[0].is_empty(), "the server read no early data");
    assert_eq!(seen.connections.load(std::sync::atomic::Ordering::SeqCst), 1, "one TCP connection carried both");
    assert_eq!(seen.openings.lock().unwrap().clone(), vec![WRITE], "the head arrived whole, once");
    let requests = seen.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "one request, not two: {requests:?}");
    assert_eq!(requests[0].1, "/ws?ed=4096");
    assert_eq!(seen.targets.lock().unwrap().len(), 1);
}

/// The nonce is not in any line of a failure, and debug prints it redacted.
#[test]
fn the_nonce_is_in_no_debug_or_line() {
    let window = Arc::new(vless::ReplayWindow::new());
    let early = vless::early::Early::new(window, b"secret-nonce");
    let text = format!("{early:?}");
    assert_eq!(text, "Early(<redacted>)");
    assert!(!text.contains("secret-nonce"));
}
