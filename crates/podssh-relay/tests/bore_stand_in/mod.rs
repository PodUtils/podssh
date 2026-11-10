//! A stand-in of bore's server (`bore server`), in the test's own process on
//! the loopback, for the tests of the bore road (T-569), written from bore's
//! source at commit `00a735a89917` (`ekzhang/bore:src/server.rs`,
//! `src/shared.rs`, `src/auth.rs`, read on 2026-11-10), with serde_json's
//! own values and an HMAC written out, not podssh's `bore::wire`:
//!
//! - each connection to the control port: with a secret, `Challenge` and a
//!   UUID first, then an `Authenticate` with the hex of HMAC-SHA256 keyed by
//!   SHA-256 of the secret over the UUID's bytes, else `Error` and the end;
//! - then one message within 3 s: `Hello(port)` makes a listener at that
//!   port of the loopback (outside the range: "client port number not in
//!   allowed range"; held: "port already in use"; 0: a free one), answered
//!   `Hello(port)`, then a `Heartbeat` at each tick, and for each visitor of
//!   the port a `Connection` with a new UUID, the visitor kept 10 s; nothing
//!   more is read on that connection, as bore's server reads nothing there;
//! - `Accept(uuid)` pipes the connection to the visitor of that UUID, raw;
//!   another UUID ends the connection.
//!
//! A restart ends each connection and each listener of a port, as bore.pub's
//! restarts do. The run against bore's own `bore server` of its release, in
//! a container, waits with the checks of a release (T-251).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// bore's wait for a first message, and for a visitor's `Accept`.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);
const STALE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct State {
    /// The visitors that wait for an `Accept`, by UUID.
    waiting: HashMap<String, TcpStream>,
    /// The tasks of the connections and the ports, which a restart ends.
    tasks: Vec<JoinHandle<()>>,
}

/// What the stand-in saw.
#[derive(Default)]
pub struct Seen {
    /// Each port that a `Hello` asked, and whether it was given.
    pub hellos: Mutex<Vec<(u16, bool)>>,
    /// The connections that took a visitor by `Accept`.
    pub accepts: AtomicUsize,
    /// The visitors of the public ports.
    pub visitors: AtomicUsize,
    /// Bytes that came on a control connection after its `Hello`, which
    /// bore's server never reads.
    pub stray: AtomicUsize,
}

/// bore's server, listening on the loopback.
pub struct StandIn {
    pub port: u16,
    pub seen: Arc<Seen>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.task.abort();
        self.restart();
    }
}

/// A new UUID's text, 8-4-4-4-12, of random bytes.
fn uuid() -> String {
    let mut bytes = [0u8; 16];
    podssh_relay::session::Entropy::fill(&mut podssh_relay::session::OsEntropy, &mut bytes).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// bore's `Authenticator::validate`: the tag is the hex of HMAC-SHA256,
/// keyed by SHA-256 of the secret, over the challenge's 16 bytes. HMAC is
/// written out here (RFC 2104), apart from the code under test, with
/// SHA-256 alone, which each crate that includes this file has.
fn valid(secret: &str, challenge: &str, tag: &str) -> bool {
    let digits = challenge.replace('-', "");
    let bytes: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).unwrap()).collect();
    // The key of 32 bytes, padded to SHA-256's block of 64.
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&Sha256::digest(secret.as_bytes()));
    let pad = |with: u8| key.iter().map(|b| b ^ with).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(&bytes).finalize();
    let outer = Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize();
    let want: String = outer.iter().map(|b| format!("{b:02x}")).collect();
    want == tag
}

async fn send(tcp: &mut TcpStream, value: Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(0);
    tcp.write_all(&bytes).await
}

/// One frame, a byte at a time, within bore's 3 s.
async fn recv(tcp: &mut TcpStream) -> Option<Value> {
    let read = async {
        let mut bytes = Vec::new();
        loop {
            match tcp.read_u8().await.ok()? {
                0 => return serde_json::from_slice(&bytes).ok(),
                byte if bytes.len() < 256 => bytes.push(byte),
                _ => return None,
            }
        }
    };
    tokio::time::timeout(NETWORK_TIMEOUT, read).await.ok().flatten()
}

impl StandIn {
    /// The server, with `secret` where it has one, giving the ports of
    /// `range` alone; its heartbeat comes each `tick` (bore's is 500 ms).
    pub async fn start(secret: Option<&str>, range: std::ops::RangeInclusive<u16>, tick: Duration) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
        let port = listener.local_addr().unwrap().port();
        let (seen, state) = (Arc::new(Seen::default()), Arc::new(Mutex::new(State::default())));
        let secret = secret.map(str::to_string);
        let task = {
            let (seen, state) = (seen.clone(), state.clone());
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (seen, inner, secret, range) = (seen.clone(), state.clone(), secret.clone(), range.clone());
                    let task = tokio::spawn(async move { control(tcp, secret, range, tick, seen, inner).await });
                    state.lock().unwrap().tasks.push(task);
                }
            })
        };
        StandIn { port, seen, state, task }
    }

    /// The ports that `Hello` asked, each with whether it was given.
    pub fn hellos(&self) -> Vec<(u16, bool)> {
        self.seen.hellos.lock().unwrap().clone()
    }

    /// The restart of bore.pub: each connection and each port ends.
    pub fn restart(&self) {
        let mut state = self.state.lock().unwrap();
        for task in state.tasks.drain(..) {
            task.abort();
        }
        state.waiting.clear();
    }
}

/// One connection to the control port, as bore's `handle_connection`.
async fn control(
    mut tcp: TcpStream,
    secret: Option<String>,
    range: std::ops::RangeInclusive<u16>,
    tick: Duration,
    seen: Arc<Seen>,
    state: Arc<Mutex<State>>,
) {
    if let Some(secret) = &secret {
        let challenge = uuid();
        let _ = send(&mut tcp, json!({ "Challenge": challenge })).await;
        let answered = match recv(&mut tcp).await {
            Some(Value::Object(map)) => map.get("Authenticate").and_then(Value::as_str).map(str::to_string),
            _ => None,
        };
        let refused = match answered {
            Some(tag) if valid(secret, &challenge, &tag) => None,
            Some(_) => Some("invalid secret"),
            None => Some("server requires secret, but no secret was provided"),
        };
        if let Some(words) = refused {
            let _ = send(&mut tcp, json!({ "Error": words })).await;
            return;
        }
    }
    let Some(Value::Object(message)) = recv(&mut tcp).await else { return };
    if let Some(port) = message.get("Hello").and_then(Value::as_u64) {
        let port = port as u16;
        let listener = match listen(port, &range).await {
            Ok(listener) => listener,
            Err(words) => {
                seen.hellos.lock().unwrap().push((port, false));
                let _ = send(&mut tcp, json!({ "Error": words })).await;
                return;
            }
        };
        let given = listener.local_addr().unwrap().port();
        seen.hellos.lock().unwrap().push((port, true));
        if send(&mut tcp, json!({ "Hello": given })).await.is_err() {
            return;
        }
        let (mut reader, mut writer) = tcp.into_split();
        // bore's server reads nothing more here: a byte that comes is stray.
        let strays = seen.clone();
        let watch = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok(n @ 1..) = reader.read(&mut buf).await {
                strays.stray.fetch_add(n, Ordering::SeqCst);
            }
        });
        loop {
            if writer.write_all(b"\"Heartbeat\"\0").await.is_err() {
                break;
            }
            let Ok(Ok((visitor, _))) = tokio::time::timeout(tick, listener.accept()).await else { continue };
            seen.visitors.fetch_add(1, Ordering::SeqCst);
            let id = uuid();
            state.lock().unwrap().waiting.insert(id.clone(), visitor);
            let stale = (state.clone(), id.clone());
            tokio::spawn(async move {
                tokio::time::sleep(STALE).await;
                stale.0.lock().unwrap().waiting.remove(&stale.1);
            });
            let mut frame = serde_json::to_vec(&json!({ "Connection": id })).unwrap();
            frame.push(0);
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
        watch.abort();
    } else if let Some(id) = message.get("Accept").and_then(Value::as_str) {
        let visitor = state.lock().unwrap().waiting.remove(id);
        let Some(mut visitor) = visitor else { return };
        seen.accepts.fetch_add(1, Ordering::SeqCst);
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut visitor).await;
    }
}

/// bore's `create_listener`, on the loopback.
async fn listen(port: u16, range: &std::ops::RangeInclusive<u16>) -> Result<TcpListener, &'static str> {
    let bind = |port: u16| async move {
        TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => "port already in use",
            std::io::ErrorKind::PermissionDenied => "permission denied",
            _ => "failed to bind to port",
        })
    };
    if port > 0 {
        if !range.contains(&port) {
            return Err("client port number not in allowed range");
        }
        return bind(port).await;
    }
    for _ in 0..150 {
        let span = u32::from(*range.end() - *range.start()) + 1;
        let mut draw = [0u8; 4];
        podssh_relay::session::Entropy::fill(&mut podssh_relay::session::OsEntropy, &mut draw).unwrap();
        let port = *range.start() + (u32::from_be_bytes(draw) % span) as u16;
        if let Ok(listener) = bind(port).await {
            return Ok(listener);
        }
    }
    Err("failed to find an available port")
}

/// A listener at `port` of the loopback that another tunnel holds: each of
/// its visitors gets another service's first line.
pub async fn squat(port: u16) -> Option<JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.ok()?;
    Some(tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tcp.write_all(b"SSH-2.0-another-tunnel's-service\r\n").await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    }))
}
