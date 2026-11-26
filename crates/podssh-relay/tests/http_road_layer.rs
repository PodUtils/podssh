//! The resumable layer over the HTTP road against podssh's relay role on the
//! loopback (`role_harness`): where a way refuses the upgrade of
//! `/v1/layer/`, each link of a session is a session of the HTTP road at
//! `/v1/http/open-layer/HOST/PORT` (or `/v1/http/one-layer/HOST/PORT`), and
//! the role gives its bytes to its layer. A new session carries bytes to an
//! echo; the role then ends each session of the road, as a role that lost
//! them, and the same session resumes on a second session of the road, with
//! the target dialed once. A wrong token is refused for good, in the layer's
//! words.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test http_road_layer
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod http_road_harness;
mod role_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_road_harness::road;
use podssh_relay::forward_layer::{carry_or_road, Dialer};
use podssh_relay::http_road::Form;
use podssh_relay::relay::Relay;
use podssh_relay::serve::http_road::sessions;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use podssh_relay::session::client;
use podssh_relay::session::resume::Note;
use podssh_relay::session::{Ask, OsEntropy, Settings};
use role_harness::Role;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

/// The bound of each wait of a test.
const LIMIT: Duration = Duration::from_secs(60);

/// The role, which dials the loopback, and a token of its own.
async fn role() -> (Role, String) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// An echo on the loopback that counts the connections it took.
async fn echo(dials: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            dials.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    port
}

/// The links of a session to the loopback's `target`, each a session of the
/// road to the role in `form`, with `token`.
fn dialer(role: &Role, token: &str, target: u16, form: Form) -> Dialer {
    let relay = Relay { host: "127.0.0.1".into(), port: role.relay.port };
    let road = road(role.relay.port, "127.0.0.1");
    let dialer = Dialer::over_road(relay, road, token, "127.0.0.1", target).expect("a target that a path names");
    dialer.with_road_form(Some(form))
}

/// `bytes` through the session and back from the echo.
async fn round(app: &mut DuplexStream, bytes: &[u8]) -> Result<(), String> {
    app.write_all(bytes).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; bytes.len()];
    match tokio::time::timeout(LIMIT, app.read_exact(&mut got)).await {
        Ok(Ok(_)) if got == bytes => Ok(()),
        Ok(Ok(_)) => Err("other bytes came back".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("no echo in time".into()),
    }
}

/// A new session of the layer on a session of the road in `form`; with
/// `cut`, the role ends each session of the road, and the same session of
/// the layer resumes on a new one.
async fn session_over(form: Form, cut: bool) {
    let (role, token) = role().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let target = echo(dials.clone()).await;
    let dialer = dialer(&role, &token, target, form);
    let first = dialer.link_or_road(&mut |_| {}).await.unwrap_or_else(|m| panic!("{form:?}: {:?}", m.lines("echo")));
    assert!(first.by_road(), "{form:?}: the first link went on the road");
    let mut entropy = OsEntropy;
    let start = client::start(first, Ask::New, Settings::default(), &mut entropy);
    let client = tokio::time::timeout(LIMIT, start).await.expect("the handshake in time").expect("a new session");
    let (mut app, theirs) = tokio::io::duplex(256 * 1024);
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let heard = notes.clone();
    let carrying = tokio::spawn(async move {
        let note = move |n: Note| heard.lock().unwrap().push(n);
        carry_or_road(&dialer, client, theirs, note).await
    });
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for n in 0..3u8 {
        round(&mut app, &[n; 100]).await.unwrap_or_else(|e| panic!("{form:?} before the cut: {e}"));
    }
    round(&mut app, &big).await.unwrap_or_else(|e| panic!("{form:?}: a large write: {e}"));
    let opened = if form == Form::One { "http one open layer" } else { "http open layer" };
    // The link's lines name the client of the road and the target (T-1035).
    let at = format!("127.0.0.1:{target}");
    let named = [("client", "127.0.0.1"), ("target", at.as_str())];
    role.assert_named(opened, &named);
    if cut {
        let ended = sessions::end_each(&role.cfg, 1001, "a test cut the link");
        assert_eq!(ended, 1, "{form:?}: one session of the road carried the link");
        let after = round(&mut app, b"after the cut").await;
        let seen = notes.lock().unwrap().clone();
        after.unwrap_or_else(|e| panic!("{form:?} after the cut: {e}; notes {seen:?}"));
        assert!(seen.iter().any(|n| matches!(n, Note::Resumed { .. })), "{form:?}: {seen:?}");
        role.assert_named("layer resumed", &named);
    }
    assert_eq!(dials.load(Ordering::SeqCst), 1, "{form:?}: the role dialed the target once for the session");
    drop(app);
    let _ = tokio::time::timeout(LIMIT, carrying).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_resumes_on_a_second_session_of_the_road_in_the_split_form() {
    session_over(Form::Split, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_resumes_on_a_second_session_of_the_road_in_the_serial_form() {
    session_over(Form::Serial, true).await;
}

/// The one-POST form keeps no session in the role's table: a new session
/// of the layer on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_goes_on_the_one_post_form() {
    session_over(Form::One, false).await;
}

/// A token that the role does not take: the link is refused for good, with
/// the layer's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_token_ends_the_link_for_good_in_the_layer_s_words() {
    let (role, _) = role().await;
    let target = echo(Arc::default()).await;
    let dialer = dialer(&role, "not-a-token-of-this-role", target, Form::Split);
    let missed = dialer.link_or_road(&mut |_| {}).await.err().expect("a refusal");
    assert!(missed.is_final(), "{:?}", missed.lines("echo"));
    let lines = missed.lines("echo").join("; ");
    assert!(lines.contains("layer: missing or wrong token"), "{lines}");
}
