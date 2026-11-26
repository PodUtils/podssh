//! The relay role's reverse road (T-427): `POST /v1/pair`, the node's socket
//! at `/v1/node/<name>`, the operator's at `/v1/connect/<name>`,
//! `GET /v1/status/<name>` and `POST /v1/stop/<name>`, as the contract
//! `2026-10-03-r2` gives them (`docs/relay.md`, "The reverse path"), so that
//! `podssh node`, `podssh operator` and `podssh ssh node://` work against
//! `podssh relay serve` with no other relay. What the default deployment does
//! not do, the role does: a bound of 1 MiB for a slow receiver (T-336), a
//! frame in flight for a session just closed dropped, not the node's socket
//! (T-421), and `1012` to each socket before a planned stop, after the frames
//! that wait for it, with no socket joining meanwhile (T-255). Beside
//! the contract, `POST /v1/renew/<name>` with the stop token renews a pair
//! for 72 h, its tokens the same, and the status names the expiry (T-592);
//! and `POST /v1/pair?once=1` makes a pair whose connect token takes one
//! upgrade alone, which `/relays.json` offers (T-226). A pair's node
//! registers tokens of one leg on its socket, each of which one operator's
//! upgrade takes, and rotates its stop token with `POST /v1/rotate/<name>`;
//! the node's `hello` and `/relays.json` offer both (T-615, [`pairs::Leg`]).
//! A role that mints for keys keeps a share of its pairs for each (T-630).
//! The owner halts a pair and resumes it with its stop token ([`halt`], T-647).
//! An upgrade of a dialect that the role does not read gets `426` ([`proto`], T-643).
//! A name that the owner publishes is a session of its pair's node ([`publish`], T-649).
//! A node that asks gets sessions readied ahead for its operators ([`spares`], T-650).
//!
//! The frames are read and written with the codecs of podssh's own node
//! (`crate::reverse::framing`, `crate::reverse::control`), so that the two
//! sides cannot drift apart; `scripts/fake_reverse.py` stays the second
//! reading of the contract. A carrier (T-595, [`carrier`]) serves the same
//! node's side and operator's side for one node over a stream of the user's,
//! in the process of its client.

pub mod carrier;
pub mod halt;
pub mod lost;
pub mod node;
pub mod operator;
pub mod outbox;
pub mod pairs;
pub mod proto;
pub mod publish;
pub mod spares;

pub use pairs::Pairs;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, Request};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

use self::pairs::{NotMade, Role};
use super::said::Of;
use super::{answer, docs, Config, Mint};
use crate::reverse::{control::PROTO, framing::SessionId};

/// The role pings an operator's or a carrier's socket this often, and drops
/// one that answers nothing for so many intervals; a node's, sooner
/// ([`lost`]), as it would else hold its name against its `409`s. The default
/// relay sends no keepalive; a Ping is no payload, and a peer answers it.
pub const PING_EVERY: Duration = Duration::from_secs(20);
pub const PINGS_ALLOWED: u32 = 3;
/// How long a socket that the role closed waits for the peer's Close.
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// A planned stop's Close (T-255): RFC 6455's "Service Restart", which a
/// client tells apart from a lost link, and connects again after.
pub const RESTART: u16 = crate::reverse::node::RESTART;
pub const RESTARTING: &str = "relay restarting";
/// How long a planned stop lets the frames that wait for a socket go out
/// before its `1012`; past it, the Close goes before them.
pub const STOP_GRACE: Duration = Duration::from_secs(1);
/// The contract's wait for a `ready`: `1013 node open timeout` after it.
pub const OPEN_WAIT: Duration = Duration::from_secs(15);
/// The contract's cap of one session, both ways together.
pub const SESSION_BYTES: u64 = 64 << 20;
/// The sessions of one node, as `hello` says them.
pub const MAX_SESSIONS: usize = 64;
/// The largest body of `/v1/pair` and `/v1/stop`, which the contract sends
/// as `{}`.
const BODY_MAX: usize = 4096;

/// Whether `path` is one of the reverse road's.
pub fn serves(path: &str) -> bool {
    let socket_or_pair = ["/v1/node/", "/v1/connect/", "/v1/status/", "/v1/stop/", "/v1/renew/", "/v1/rotate/"];
    let halting = ["/v1/halt/", "/v1/resume/"];
    path == "/v1/pair" || socket_or_pair.iter().chain(&halting).any(|p| path.starts_with(p))
}

/// Serve one request of the reverse road on `stream`, of a client at `from`
/// whom its lines name, with its pair once it has one (T-1035).
pub async fn request<S>(
    mut stream: S,
    head: Request,
    pending: Vec<u8>,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    // A request that is no upgrade has its body read first, `{}` at most: a
    // byte left unread would make the end of the connection a reset, which
    // can lose the answer.
    let (pending, sent) = if head.has_token("upgrade", "websocket") {
        (pending, Vec::new())
    } else {
        match super::body(&mut stream, &head, pending, BODY_MAX, &path).await {
            Ok(sent) => (Vec::new(), sent),
            Err(refusal) => return answer(&mut stream, refusal).await,
        }
    };
    if path == "/v1/pair" {
        return pair(&mut stream, &head, &sent, &cfg, sni.as_deref(), from).await;
    }
    let mut parts = path.trim_start_matches('/').splitn(3, '/');
    let (Some("v1"), Some(kind), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return answer(&mut stream, request::refusal(404, &format!("{path}: not found"), &[])).await;
    };
    let role = match kind {
        "node" => Role::Node,
        "connect" | "status" => Role::Connect,
        _ => Role::Stop,
    };
    let now = super::tokens::now_ms();
    let token = token_of(&head);
    let found =
        crate::relay::check_node_name(name).ok().and_then(|()| cfg.pairs.find(name, role, token.as_deref(), now));
    // A token of one leg that the pair's node registered (T-615), for the
    // upgrade of an operator alone.
    let (found, leg) = match (found, kind) {
        (None, "connect") => match cfg.pairs.find_leg(name, token.as_deref(), now) {
            Some((pair, digest)) => (Some(pair), Some(digest)),
            None => (None, None),
        },
        (found, _) => (found, None),
    };
    // Each failed authentication looks the same, as on the default relay.
    let Some(pair) = found else {
        return answer(&mut stream, request::refusal(403, "reverse: forbidden", &[])).await;
    };
    // Each line from here on is this pair's.
    let of = Of::client(from).with_pair(&pair.name);
    // A dialect that the role does not read, said once the token passed and
    // before a token of `once` or of one leg is spent (T-643).
    if matches!(kind, "node" | "connect") && proto::refused(&mut stream, &head, kind).await {
        return;
    }
    // A halted pair refuses each operator with its owner's words before a
    // token of `once` or of one leg is spent (T-647); a planned stop's first.
    if kind == "connect" && !cfg.pairs.stopping() && halt::refused(&mut stream, &pair).await {
        return;
    }
    // It takes this upgrade and no other; a planned stop refuses it below, as
    // it refuses each socket.
    if let (Some(digest), false) = (leg, cfg.pairs.stopping()) {
        return leg_upgrade(stream, head, pending, pair, digest, cfg, of).await;
    }
    let method = head.method.clone();
    match (kind, method.as_str()) {
        ("status", "GET") => {
            let (online, sessions, halted) = {
                let state = pair.lock();
                (state.node_outbox().is_some(), state.sessions.len(), state.halted.clone())
            };
            // The expiry beside the contract's fields, which a renewal moves
            // (T-592), so that an operator's file need not name it; a halt.
            let mut body = json!({ "online": online, "sessions": sessions, "expires": pair.expires_ms() });
            halt::status(&mut body, halted.as_ref());
            answer(&mut stream, docs::json(&body)).await
        }
        ("stop", "POST") => {
            let (stopped, sessions) = cfg.pairs.end(name, 1001, "operator stopped reverse relay").unwrap_or((false, 0));
            cfg.event_of(&of, "reverse stop");
            answer(&mut stream, docs::json(&json!({ "stopped": stopped, "sessions": sessions }))).await
        }
        ("renew", "POST") => renew(&mut stream, name, &cfg, &of).await,
        ("rotate", "POST") => rotate(&mut stream, name, &sent, &cfg, &of).await,
        ("halt", "POST") => halt::serve_halt(&mut stream, name, &sent, &cfg, &of).await,
        ("resume", "POST") => halt::serve_resume(&mut stream, name, &cfg, &of).await,
        // A planned stop closes each socket: one that would join now would
        // be cut with no Close, so it waits for the role that comes back.
        ("node" | "connect", _) if cfg.pairs.stopping() => {
            let why = format!("reverse: {RESTARTING}");
            answer(&mut stream, request::refusal(503, &why, &[("Retry-After", "1")])).await
        }
        ("node", _) => node::join(stream, head, pending, pair, cfg, of).await,
        // A connect token of `once` takes this upgrade, and no other (T-226).
        ("connect", _) if !cfg.pairs.spend_connect(&pair) => {
            cfg.event_of(&of, "reverse connect token spent");
            answer(&mut stream, request::refusal(403, "reverse: forbidden", &[])).await
        }
        ("connect", _) => operator::join(stream, head, pending, pair, cfg, None, of).await,
        (_, method) => {
            let allow = if matches!(kind, "stop" | "renew" | "rotate" | "halt" | "resume") { "POST" } else { "GET" };
            let why = format!("{path}: not {method}, but {allow}");
            answer(&mut stream, request::refusal(405, &why, &[("Allow", allow)])).await
        }
    }
}

/// `POST /v1/pair`: `{name, node_token, connect_token, stop_token, expires}`,
/// for whom the role mints tokens; its line names the pair made.
async fn pair<S>(stream: &mut S, head: &Request, body: &[u8], cfg: &Config, sni: Option<&str>, from: Option<IpAddr>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if head.method != "POST" {
        let why = format!("/v1/pair: not {}, but POST", head.method);
        return answer(stream, request::refusal(405, &why, &[("Allow", "POST")])).await;
    }
    if matches!(cfg.mint, Mint::Nobody) {
        let why = "/v1/pair: this relay makes no pair, as it mints no token; its owner gives them";
        return answer(stream, request::refusal(503, why, &[])).await;
    }
    let empty = body.iter().all(u8::is_ascii_whitespace);
    if !empty && !serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| v.is_object()) {
        return answer(stream, request::refusal(400, "/v1/pair: the body is {} or nothing", &[])).await;
    }
    // For the keys of a list, as the mint (T-448).
    let maker = match super::proven(cfg, head, sni, "/v1/pair", body) {
        Ok(maker) => maker,
        Err(refusal) => return answer(stream, refusal).await,
    };
    // `?once=1`: a connect token that takes one upgrade alone (T-226); the
    // query holds no credential, and the proof of a key signs the path.
    let query = head.target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let once = query.split('&').any(|p| p == "once=1" || p == "once=true");
    // Within its share of the table, among the keys that the role mints for
    // now (T-630).
    let keys = super::keys::Whom::of(&cfg.mint).map_or(0, |whom| whom.count());
    let asker = maker.map(|key| pairs::Asker { key: key.fingerprint(), keys });
    let made = match cfg.pairs.make_for(super::tokens::now_ms(), once, asker.as_ref()) {
        Ok(made) => made,
        Err(NotMade::NameInUse) => {
            return answer(stream, request::refusal(409, "/v1/pair: the name drawn is in use; pair again", &[])).await
        }
        Err(NotMade::Full) => {
            let why = format!("/v1/pair: this relay keeps {} pairs already", cfg.pairs.room());
            return answer(stream, request::refusal(429, &why, &[("Retry-After", "60")])).await;
        }
        // The key's own count and share, and no word of another key's.
        Err(NotMade::Share { holds, share }) => {
            cfg.event_of(&Of::client(from), &format!("/v1/pair: a key past its share of {share} pairs"));
            let why = format!("/v1/pair: this key holds {holds} pairs, past its share of {share} while others wait");
            return answer(stream, request::refusal(429, &why, &[("Retry-After", "60")])).await;
        }
        Err(NotMade::Failed(why)) => {
            return answer(stream, request::refusal(503, &format!("/v1/pair: {why}"), &[])).await;
        }
    };
    cfg.event_of(&Of::client(from).with_pair(&made.name), "reverse pair");
    let mut body = json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    // Said only when asked, so that the answer of a pair of before stays
    // the contract's.
    if made.once {
        body["once"] = json!(true);
    }
    answer(stream, docs::json(&body)).await;
}

/// `POST /v1/renew/<name>`, whose stop token was checked (T-592): the pair
/// ends 72 h from now, never earlier than it did, with its three tokens, so
/// that each operator's file keeps working; `{"expires": ...}`. A pair that
/// ended meanwhile gets the `403` of each failed authentication.
async fn renew<S>(stream: &mut S, name: &str, cfg: &Config, of: &Of)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match cfg.pairs.renew(name, super::tokens::now_ms()) {
        Ok(Some(expires)) => {
            cfg.event_of(of, "reverse renew");
            answer(stream, docs::json(&json!({ "expires": expires }))).await
        }
        Ok(None) => answer(stream, request::refusal(403, "reverse: forbidden", &[])).await,
        Err(why) => answer(stream, request::refusal(503, &format!("/v1/renew: {why}"), &[])).await,
    }
}

/// An operator's upgrade by the token of one leg `digest` (T-615): taken
/// only while the pair's node is there to hear of it, as it then registers
/// the next one; else `503`, and the token waits for the node. A token that
/// another upgrade took meanwhile gets the `403` of each failed
/// authentication.
async fn leg_upgrade<S>(
    mut stream: S,
    head: Request,
    pending: Vec<u8>,
    pair: Arc<pairs::Pair>,
    digest: [u8; 32],
    cfg: Arc<Config>,
    of: Of,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // A request that is no upgrade spends nothing.
    if let Err(refused) = podssh_ws::server::check_upgrade(&head) {
        return answer(&mut stream, refused.answer()).await;
    }
    match cfg.pairs.spend_leg(&pair, &digest, super::tokens::now_ms()) {
        pairs::Leg::Taken => {
            cfg.event_of(&of, "reverse leg token");
            operator::join(stream, head, pending, pair, cfg, Some(digest), of).await
        }
        pairs::Leg::NoNode => {
            let why = "reverse: node unavailable";
            answer(&mut stream, request::refusal(503, why, &[("Retry-After", "1")])).await
        }
        pairs::Leg::Refused => {
            cfg.event_of(&of, "reverse leg token refused");
            answer(&mut stream, request::refusal(403, "reverse: forbidden", &[])).await
        }
    }
}

/// `POST /v1/rotate/<name>` with `{"digest": HEX}`, whose stop token was
/// checked (T-615): HEX, the SHA-256 of a stop token that the node drew, is
/// the one to come, whose first use makes it the pair's and ends each before
/// it; `{"rotated": true}`. The new token crosses no wire before its use.
async fn rotate<S>(stream: &mut S, name: &str, body: &[u8], cfg: &Config, of: &Of)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let asked: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let digest = asked.as_ref().and_then(|a| a.get("digest")).and_then(serde_json::Value::as_str);
    let Some(next) = digest.and_then(pairs::parse_digest) else {
        let why = "/v1/rotate: the body is {\"digest\": the SHA-256 of the next stop token, in 64 hex digits}";
        return answer(stream, request::refusal(400, why, &[])).await;
    };
    match cfg.pairs.rotate(name, next, super::tokens::now_ms()) {
        Ok(Some(())) => {
            cfg.event_of(of, "reverse rotate");
            answer(stream, docs::json(&json!({ "rotated": true }))).await
        }
        Ok(None) => answer(stream, request::refusal(403, "reverse: forbidden", &[])).await,
        Err(why) => answer(stream, request::refusal(503, &format!("/v1/rotate: {why}"), &[])).await,
    }
}

/// The token of a reverse request: its `X-Relay-Token`, else its `?token=`,
/// the two places that the contract names.
fn token_of(head: &Request) -> Option<String> {
    if let Some(token) = head.header("x-relay-token") {
        return Some(token.to_string());
    }
    let query = head.target.split_once('?').map(|(_, q)| q)?;
    query.split('&').find_map(|p| p.strip_prefix("token=")).map(str::to_string)
}

/// A new session's id: 32 lowercase hex characters, as the contract gives.
fn new_id() -> Option<SessionId> {
    let bytes = pairs::random(16).ok()?;
    SessionId::parse(pairs::hex(&bytes).as_bytes()).ok()
}

/// The node's first frame, as the default relay sends it (measured
/// 2026-10-09), its version the role's dialect (T-643); with `offers`, the
/// role's tokens of one leg and the stop token's rotation beside it (T-615),
/// its halt (T-647) and its sessions readied ahead (T-650), which a node of
/// before keeps as fields that it does not know.
fn hello(offers: bool) -> String {
    let mut hello = json!({ "type": "hello", "version": PROTO, "maxFrameBytes": 65536, "maxSessions": MAX_SESSIONS });
    if offers {
        hello[crate::e2e::legs::OFFER] = json!(true);
        hello[crate::reverse::legs::ROTATION] = json!(true);
        hello[halt::OFFER] = json!(true);
        hello[spares::OFFER] = json!(true);
    }
    hello.to_string()
}

/// `spent {digest}` to the node, before the `open` of the session whose
/// upgrade took the token of one leg of `digest` (T-615).
fn spent(digest: &[u8; 32]) -> String {
    json!({ "type": "spent", "digest": pairs::hex(digest) }).to_string()
}

/// `open {id}` to the node.
fn open(id: &SessionId) -> String {
    json!({ "type": "open", "id": id.as_str() }).to_string()
}

/// `close {id}` to the node, with the relay's reason when it ended the
/// session itself; with none when the operator left, as the default relay.
fn close(id: &SessionId, why: Option<&str>) -> String {
    match why {
        Some(why) => json!({ "type": "close", "id": id.as_str(), "reason": why }).to_string(),
        None => json!({ "type": "close", "id": id.as_str() }).to_string(),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
