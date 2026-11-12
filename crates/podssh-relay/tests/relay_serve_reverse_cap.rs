//! The node's journal line for a session that the relay closed at its byte
//! cap (T-701, GitHub #167), against podssh's relay role: podssh's own node
//! (`reverse::run`) behind a pair of the role, and an operator whose echoed
//! session carries more than the contract's 64 MiB, both ways together. The
//! role ends it with `close {id, reason: "session byte cap"}`, and the node's
//! writer says one line of it where the budget's lines go
//! (`session::budget::tell`, the node's stderr): the first 8 characters of the
//! session's id and the reason. A session that ends by its operator's end of
//! input, before it, says nothing.
//!
//! The planted defect: the node's reader drops the reason again (`reason` is
//! `None` in `Out::Closed(id, reason)` of `reverse/serve.rs`), so that the
//! line never comes.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, operator, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Outcome, SessionId, Wire};
use podssh_ws::{ProxyChoice, Trust};
use role_harness::{Role, LIMIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

const MIB: usize = 1 << 20;
/// The most bytes of an echoed session in flight at once: under each bound
/// of the road, as the layer's window keeps a session under them.
const WINDOW: usize = 256 * 1024;

/// Each session echoes what it takes.
struct Echo(AtomicUsize);

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// podssh's node for `pair`, on the plain wire, until `stop`.
async fn node(pair: Pair, stop: oneshot::Receiver<()>) -> Exit {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        ctx: &podssh_relay::context::of(&proxy),
        timeout: LIMIT,
        // The node of the process, whose lines go where podssh sends them.
        settings: reverse::settings(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    reverse::run(&mut config, Arc::new(Echo(AtomicUsize::new(0))), async {
        let _ = stop.await;
    })
    .await
}

/// podssh's operator on `name`: `sent` bytes of a pattern go up and come back
/// (at most WINDOW in flight), then the input ends. Its outcome, and how many
/// bytes came back.
async fn operate(role: &Role, name: &str, token: &str, sent: usize) -> (Outcome, usize) {
    let config = OperatorConfig {
        relay: &role.relay,
        name,
        connect_token: token,
        trust: &Trust::Default,
        ctx: &podssh_relay::context::of(&ProxyChoice::Direct),
        timeout: LIMIT,
        limits: OperatorLimits::default(),
        wire: Wire::PlainLoopback,
    };
    let (app, leg) = tokio::io::duplex(64 * 1024);
    let (mut r, mut w) = tokio::io::split(app);
    let carry = async {
        let (mut got, mut at) = (0usize, 0usize);
        let (piece, mut buf) = (vec![0x5a_u8; 16 * 1024], vec![0u8; 16 * 1024]);
        while got < sent {
            let room = at < sent && at - got < WINDOW;
            tokio::select! {
                written = w.write(&piece[..piece.len().min(sent - at)]), if room => match written {
                    Ok(n) => at += n,
                    Err(_) => break,
                },
                read = r.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                },
            }
        }
        // The end of the input ends an echoed session.
        let _ = w.shutdown().await;
        got
    };
    let (outcome, got) = tokio::join!(operator::run(&config, leg), carry);
    (outcome.expect("the operator's socket"), got)
}

/// Until `lines` holds `n` lines, `LIMIT` at most.
async fn until_lines(lines: &Mutex<Vec<String>>, n: usize) {
    let deadline = Instant::now() + LIMIT;
    while lines.lock().unwrap().len() < n {
        assert!(Instant::now() < deadline, "the node's lines: {:?}", lines.lock().unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// T-701: the role's close at its cap reaches the node's journal, with the
// session's id and the reason, once; a session that ended normally before
// said nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_the_role_closes_at_its_byte_cap_is_named_in_the_nodes_journal() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let kept = lines.clone();
    // One test in this binary, so the first call is the one that holds.
    podssh_relay::session::budget::tell(move |line| kept.lock().unwrap().push(line.to_string()));
    let role = Role::start().await;
    let pair = role.pair();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let (stop, stopped) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        // A normal end first: the operator's input ends, the session closes.
        let (normal, got) = operate(&role, &name, &token, 64 * 1024).await;
        assert!(normal.is_success() && got == 64 * 1024, "{normal:?} {got}");
        // Let the node's writer take the close of that session, if it said one.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = lines.lock().unwrap().clone();
        // 34 MiB up and the same back: 68 MiB, both ways together.
        let capped = operate(&role, &name, &token, 34 * MIB).await;
        until_lines(&lines, 1).await;
        let _ = stop.send(());
        (before, capped)
    };
    let ((before, (outcome, got)), exit) =
        tokio::time::timeout(4 * LIMIT, async { tokio::join!(test, node(pair, stopped)) }).await.expect("in time");
    assert!(before.is_empty(), "a normal close says nothing: {before:?}");
    assert!(
        matches!(&outcome, Outcome::Ended { code: 1009, reason } if reason == "session byte cap"),
        "the role closed the session at its cap: {outcome:?}, {got} bytes came back"
    );
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    let said = lines.lock().unwrap().clone();
    assert_eq!(said.len(), 1, "one line for the close: {said:?}");
    let line = &said[0];
    let id = line.strip_prefix("the relay closed session ").and_then(|rest| rest.strip_suffix("...: session byte cap"));
    assert!(id.is_some_and(|id| id.len() == 8), "the first 8 characters of the id and the reason: {line:?}");
}
