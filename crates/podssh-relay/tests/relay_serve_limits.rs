//! The limits of podssh's relay role that `podssh relay serve` takes as
//! flags (T-704: `--idle`, `--max-session-mib`), enforced on a forward
//! session as the contract's words say: the idle cut closes a silent session
//! with `1001 idle timeout`, and the byte cap one that carried more with
//! `1009 session byte cap`. A raw socket speaks for the client, so that no
//! layer of podssh's own client carries the session past the cut.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::time::Duration;

use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Limits};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use role_harness::{next, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// A target on the loopback that holds its one client and sends `bytes`
/// at once, then says nothing; it reads and drops what comes.
async fn target(bytes: usize) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else { return };
        let _ = tcp.write_all(&vec![7u8; bytes]).await;
        let mut sink = [0u8; 4096];
        while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    port
}

/// A forward session to `port` through a role with `limits`.
async fn forward(port: u16, limits: Limits) -> (Role, RelaySession<TcpStream>) {
    let role = Role::limited(Policy { private: true, ..Policy::default() }, limits).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let session = role.socket(&format!("/connect/127.0.0.1/{port}"), &token).await.expect("a forward session");
    (role, session)
}

/// The payload until the role's Close, and the Close; none within `wait`.
async fn until_close(socket: &RelaySession<TcpStream>, wait: Duration) -> (usize, (Option<u16>, String)) {
    let mut payload = 0;
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, next(socket)).await {
            Ok(Some((OPCODE_BINARY, bytes))) => payload += bytes.len(),
            Ok(Some((OPCODE_CLOSE, close))) => return (payload, close_code_and_reason(&close)),
            Ok(Some(_)) => {}
            Ok(None) => return (payload, (None, "the socket ended with no Close".into())),
            Err(_) => return (payload, (None, format!("no Close within {wait:?}"))),
        }
    }
}

/// `--idle 2`: a session with no payload either way for 2 s ends with the
/// contract's `1001 idle timeout`, not before; the role's keepalives, empty
/// frames, are no payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_idle_cut_closes_a_silent_session_with_1001() {
    let port = target(0).await;
    let limits = Limits { idle: Duration::from_secs(2), keepalive: Duration::from_millis(500), ..Limits::default() };
    let (_role, client) = forward(port, limits).await;
    let opened = Instant::now();
    let (_, close) = until_close(&client, Duration::from_secs(15)).await;
    assert_eq!(close, (Some(1001), "idle timeout".to_string()));
    let took = opened.elapsed();
    assert!(took >= Duration::from_millis(1800), "closed before the idle cut was due: {took:?}");
}

/// `--max-session-mib 1`: a target that sends 8 MiB has its session ended
/// with the contract's `1009 session byte cap`, with no more than the cap and
/// one read of the target's in flight past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_byte_cap_ends_a_session_that_carries_more_with_1009() {
    let port = target(8 << 20).await;
    let (_role, client) = forward(port, Limits { bytes: 1 << 20, ..Limits::default() }).await;
    let (got, close) = until_close(&client, Duration::from_secs(15)).await;
    assert_eq!(close, (Some(1009), "session byte cap".to_string()));
    assert_eq!(got, 1 << 20, "the cap's bytes and not one more, of 8 MiB that the target sent");
}
