//! The relay as a role of podssh (T-169, the operator's ruling Q63): the
//! forward road of the relay's contract, version `2026-10-03-r2`, and its
//! reverse road (T-427, [`reverse`]), served by podssh itself, so that each
//! client of podssh and each test of both roads works against it unchanged
//! (`docs/relay.md`, `docs/mesh.md`). The caller owns the listener and TLS
//! (`podssh relay serve`); this serves one connection's request, and brakes
//! the mints and pairs of each address ([`brake`], T-454). Behind a quick
//! tunnel, the node's origin is the role, with no listener (T-428,
//! `behind`). Its targets are dialed through the host's proxy when one is
//! set ([`egress`], T-457), and an IPv6 target that its host cannot route
//! out is refused before the upgrade ([`ipv6`], T-253). Its probes tell a
//! client what the path does to a stream ([`probe`], T-325), and its HTTP
//! road carries a session where the upgrade is refused on the way
//! ([`http_road`], T-319). The role's own listener takes TLS, or the
//! cleartext road beside it by the first byte ([`listener`], [`cleartext`],
//! T-326), with tokens of one session alone, and an SSH client to the
//! owner's sshd where one is named ([`sshd`], T-644).
//! Beside the contract, its forward road in the resumable layer keeps a
//! standard sshd's connection across a drop of the client's link ([`layer`],
//! T-173).
//! Its mailbox is a meeting point of the pairing by a short code
//! ([`mailbox`], T-086). Beside the listener, QUIC on the same port of UDP
//! carries each stream as a connection to these routes (`quic`, feature
//! `quic`, T-667). What each key carried, and its budget for a day, are
//! counted for each session of the forward road ([`usage`], T-636). A name
//! that the owner publishes goes to its pair's node by the ClientHello, before
//! the role's own TLS ([`published`], [`sni`], T-649). With a file of node
//! keys, it serves DERP at `/derp` for them, which a node of `podssh ts` in
//! `relay` mode pins (`derp`, T-106). Where its owner names them, iroh's
//! relay protocol and the probes of iroh's and Tailscale's reports of the
//! network share the same listener ([`meet`], T-720).

#[cfg(feature = "quick")]
pub mod behind;
pub mod brake;
pub mod cleartext;
// The owner's control socket of a cover role (T-767).
pub mod control;
// The static cover site and its credential (T-764, T-765).
pub mod cover;
// DERP over a WebSocket for the node keys of its owner's file (T-106).
#[cfg(feature = "derp")]
pub mod derp;
pub mod docs;
pub mod egress;
pub mod forward;
pub mod http_road;
// HTTP/2 with extended CONNECT at the role's listener (T-321).
pub mod http2;
pub mod ipv6;
pub mod keys;
pub mod layer;
pub mod leg;
pub mod listener;
pub mod mailbox;
// iroh's relay protocol and the probes of a net's meeting point (T-720).
pub mod meet;
pub mod policy;
pub mod probe;
// The names published to nodes, routed by the ClientHello (T-649).
pub mod proxy_header;
pub mod published;
// QUIC on UDP beside the listener, each stream a connection (T-667).
#[cfg(feature = "quic")]
pub mod quic;
// The ranges of addresses that its owner lets it dial (T-635), which an
// exit's and the net's routes read too.
pub mod ranges;
pub mod reverse;
// The shape of an event line: its words, then its fields (T-1016).
pub mod said;
// The one request on one surface, and the credential of a cover (T-764 to
// T-767).
mod routes;
// The name of a ClientHello, read before any handshake (T-649).
pub mod sni;
// The listener's open connections, bounded (T-748).
pub mod slots;
pub mod sockets;
pub mod sshd;
// The role's public routes as one allow-list (T-767).
pub mod surface;
pub mod tokens;
pub mod usage;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, read_request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The contract that the role serves.
pub const CONTRACT: &str = "2026-10-03-r2";
/// How long a client has to send its request's head.
const HEAD_WAIT: Duration = Duration::from_secs(30);
/// The largest body of a mint, which the contract sends as `{}`.
const MINT_BODY: usize = 4096;

/// The contract's limits (`docs/relay.md`, "Limits that users see").
#[derive(Debug, Clone)]
pub struct Limits {
    /// The dial of a target, before the upgrade.
    pub connect: Duration,
    /// No payload either way for this long ends a session.
    pub idle: Duration,
    pub session: Duration,
    /// Payload bytes, both ways together.
    pub bytes: u64,
    /// An empty binary frame to the client this often.
    pub keepalive: Duration,
    /// After the client's Close, the target's bytes go on until it is silent
    /// this long (T-671).
    pub half_closed: Duration,
    /// The open connections of the listener, by address and in all (T-748).
    pub connections: slots::Caps,
}

impl Default for Limits {
    /// The compiled caps of the default relay: the `pod-services` facts that
    /// `relay.rs` reads, so that the role and its clients have one source
    /// (T-704).
    fn default() -> Self {
        Limits {
            connect: crate::relay::connect_timeout(),
            idle: Duration::from_secs(crate::relay::relay_idle_secs()),
            session: crate::relay::session_time_cap(),
            bytes: crate::relay::session_byte_cap(),
            keepalive: Duration::from_secs(25),
            half_closed: Duration::from_secs(15),
            connections: slots::Caps { per_address: slots::PER_ADDRESS, total: 0 },
        }
    }
}

/// Who may mint a token, and make a pair.
#[derive(Clone)]
pub enum Mint {
    /// Anyone, as the default relay mints.
    Anyone,
    /// No one: `503`, which a client reads as "do not retry"; tokens come
    /// another way.
    Nobody,
    /// The keys of this list, each by its signature of a challenge (T-448):
    /// a file, or the copy of a URL's (T-646).
    Keys(keys::List),
    /// The members of the net that the binary reads (T-455), each by the
    /// same signature, and the keys of a list beside them when one is named.
    Net(Arc<dyn keys::Members>, Option<keys::List>),
}

impl Mint {
    /// Its word in `/health`.
    pub fn word(&self) -> &'static str {
        match self {
            Mint::Anyone => "anyone",
            Mint::Nobody => "nobody",
            Mint::Keys(_) => "keys",
            Mint::Net(_, None) => "net",
            Mint::Net(_, Some(_)) => "net,keys",
        }
    }
}

impl std::fmt::Debug for Mint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mint::Anyone => f.write_str("Anyone"),
            Mint::Nobody => f.write_str("Nobody"),
            Mint::Keys(list) => f.debug_tuple("Keys").field(list).finish(),
            // The net is the binary's, and has no words of its own here.
            Mint::Net(_, list) => f.debug_tuple("Net").field(list).finish(),
        }
    }
}

/// Where a role says each mint, upgrade and client's Close.
pub type Events = Box<dyn Fn(&str) + Send + Sync>;

/// What a role serves, and how.
pub struct Config {
    /// Said in `/health`, `/relays.json` and `/trace`.
    pub version: String,
    pub mint: Mint,
    pub tokens: tokens::Tokens,
    pub policy: policy::Policy,
    /// How its targets are dialed: directly, or through the host's proxy
    /// (T-457).
    pub egress: egress::Egress,
    pub limits: Limits,
    /// The pairs of the reverse road, and their sockets. Shared, so that a
    /// role's listeners see the one table of pairs.
    pub pairs: Arc<reverse::Pairs>,
    /// The sessions of the forward road in the resumable layer, with their
    /// targets, across links (T-173).
    pub resumes: layer::Resumes,
    /// The challenges that a key answered (T-448).
    pub answered: keys::Answered,
    /// The counts of `/v1/mint` and `/v1/pair` for each address (T-454).
    pub brake: brake::Brake,
    /// What each key carried, and its budget for a day (T-636).
    pub usage: usage::Usage,
    /// The static site of a published cover name, and the key of its
    /// delegated credential (T-764); none unless `--cover`.
    pub cover: Option<Arc<cover::Cover>>,
    /// Each mint, upgrade, read of `/relays.json` and client's Close as a
    /// line (`mint`, `upgrade`, `relays.json`, `close CODE`), and each step of
    /// the reverse road (`reverse ...`), with the words that the stand-in
    /// relay prints first; a session's lines end with its fields
    /// ([`said`], T-1016).
    pub events: Option<Events>,
}

impl Config {
    fn event(&self, line: &str) {
        if let Some(say) = &self.events {
            say(line);
        }
    }

    /// A line of `words` for the connection `of`: its client, and its
    /// target where it has one (T-1016).
    fn event_of(&self, of: &said::Of, words: &str) {
        if self.events.is_some() {
            self.event(&of.line(words));
        }
    }

    /// The answer of a refusal of `of`'s request, and its line, `refused
    /// STATUS WHY client=... target=...|pair=...`: one place for each
    /// refusal of a session, so that none goes unsaid (T-1050). `logged`,
    /// where the role keeps a cause that the client does not get, is said
    /// in place of `WHY`.
    fn refused(&self, of: &said::Of, status: u16, why: &str, logged: Option<String>) -> Vec<u8> {
        self.refused_with(of, status, why, logged, &[])
    }

    /// [`Config::refused`], with the answer's own headers.
    fn refused_with(
        &self,
        of: &said::Of,
        status: u16,
        why: &str,
        logged: Option<String>,
        headers: &[(&str, &str)],
    ) -> Vec<u8> {
        self.say_refused(of, status, why, logged);
        request::refusal(status, why, headers)
    }

    /// The line of [`Config::refused`] alone, for a road that answers in its
    /// own form (the HTTP road).
    fn say_refused(&self, of: &said::Of, status: u16, why: &str, logged: Option<String>) {
        match logged {
            Some(line) => self.event_of(of, &line),
            None => self.event_of(of, &format!("refused {status} {why}")),
        }
    }
}

/// Whether `path`, with no query, is one of the role's, as
/// [`serve_named`] routes them: what the node of a quick tunnel gives the
/// role in place of its 404 (T-428). Each path under `/v1/` is the role's,
/// which answers the ones that it does not know.
pub fn serves(path: &str) -> bool {
    matches!(path, "/health" | "/v1/mint" | "/relays.json" | "/trace" | "/llms-full.txt")
        || path.starts_with("/connect/")
        || path.starts_with("/v1/")
        || meet::serves(path)
}

/// Serve the one request of `stream`, which closes after it as each request
/// of the contract is one connection's.
pub async fn serve_connection<S>(stream: S, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_named(stream, cfg, None).await
}

/// [`serve_connection`] for a stream whose TLS asked for the name `sni`: a
/// key's signed request must name it (T-448).
pub async fn serve_named<S>(stream: S, cfg: Arc<Config>, sni: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_from(stream, cfg, sni, None).await
}

pub use routes::{serve_from, serve_local, serve_tls};

/// The head of a connection's one request, the bytes after it, and its path
/// with no query; `None` once a refusal went, or when the client went away
/// or was too slow.
pub(super) async fn head_of<S>(stream: &mut S) -> Option<(request::Request, Vec<u8>, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (head, pending) = match tokio::time::timeout(HEAD_WAIT, read_request(stream, Vec::new())).await {
        Ok(Ok(read)) => read,
        Ok(Err(e)) => {
            if let Some(status) = e.status() {
                answer(stream, request::refusal(status, &e.to_string(), &[])).await;
            }
            return None;
        }
        Err(_) => return None,
    };
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    Some((head, pending, path))
}

/// `POST /v1/mint`: `{token, expires, scope}`; with `?once=1`, a token of
/// one session, `"once": true` (T-326). Its line names the client at `from`.
pub(super) async fn mint<S>(
    stream: &mut S,
    head: &request::Request,
    pending: Vec<u8>,
    cfg: &Config,
    sni: Option<&str>,
    from: Option<IpAddr>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The body first: a byte left unread would make the end of the
    // connection a reset, which can lose the answer.
    let sent = match body(stream, head, pending, MINT_BODY, "/v1/mint").await {
        Ok(sent) => sent,
        Err(refusal) => return answer(stream, refusal).await,
    };
    if matches!(cfg.mint, Mint::Nobody) {
        let why = "/v1/mint: this relay mints no token; its owner gives them";
        return answer(stream, request::refusal(503, why, &[])).await;
    }
    // The key that proved itself counts each session of the token (T-636).
    let maker = match proven(cfg, head, sni, "/v1/mint", &sent) {
        Ok(maker) => maker.map(|key| key.fingerprint()),
        Err(refusal) => return answer(stream, refusal).await,
    };
    // A token of one session, which an upgrade spends: the one that the
    // cleartext road asks for, and the only one minted in cleartext.
    if cleartext::once_asked(&head.target) {
        cfg.event_of(&said::Of::client(from), "mint once");
        let body = match cfg.tokens.mint_once(tokens::now_ms()) {
            Ok((token, expires)) => {
                // Its nonce is drawn: no other key holds it.
                if let Some(key) = &maker {
                    cfg.usage.minted(&token, key, expires);
                }
                serde_json::json!({ "token": token, "expires": expires, "scope": "forward", "once": true })
            }
            Err(why) => return answer(stream, request::refusal(503, &format!("/v1/mint: {why}"), &[])).await,
        };
        return answer(stream, docs::json(&body)).await;
    }
    cfg.event_of(&said::Of::client(from), "mint");
    let Some((token, expires)) = forward_token(cfg, maker.as_deref()) else {
        let why = "/v1/mint: mints of one millisecond made one token for several keys; ask again";
        return answer(stream, request::refusal(503, why, &[("Retry-After", "1")])).await;
    };
    let body = serde_json::json!({ "token": token, "expires": expires, "scope": "forward" });
    answer(stream, docs::json(&body)).await;
}

/// A token of the contract's form, and its end, kept for `maker`'s count
/// when a key proved itself (T-636). Two mints in one millisecond make one
/// token, which counts for one key alone, so another key's is made a
/// millisecond shorter, 64 times at most.
fn forward_token(cfg: &Config, maker: Option<&str>) -> Option<(String, u64)> {
    let now = tokens::now_ms();
    for shorter in 0..64 {
        let (token, expires) = cfg.tokens.mint(now, tokens::LIFETIME_MS - shorter);
        let kept = match maker {
            None => true,
            Some(key) => cfg.usage.minted(&token, key, expires),
        };
        if kept {
            return Some((token, expires));
        }
    }
    None
}

/// The brake's `429`, with the seconds to wait in `Retry-After`, which
/// podssh's client says. The body is read first, as for each answer.
pub(super) async fn slow_down<S>(
    stream: &mut S,
    head: &request::Request,
    pending: Vec<u8>,
    path: &str,
    braked: brake::Braked,
    cfg: &Config,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = body(stream, head, pending, MINT_BODY, path).await;
    let limit = cfg.brake.limit();
    // Once for each address that meets the brake, not for each request: the
    // address itself is not said.
    if braked.first {
        cfg.event(&format!("{path}: braked, an address past {limit} requests in a minute"));
    }
    let wait = braked.wait_s.to_string();
    let why = format!("{path}: {limit} requests of this address in a minute; ask again in {wait} s");
    answer(stream, request::refusal(429, &why, &[("Retry-After", wait.as_str())])).await;
}

/// Whether the upgrade or open of `head` at `path` may be checked: `Err`
/// once the address of `from` filled its minute; a token missing or wrong
/// counts a strike against that address (T-806). A token that the role
/// minted, and that a later check refuses (its policy, its road), is none.
pub(super) fn strike(
    cfg: &Config,
    head: &request::Request,
    path: &str,
    from: Option<IpAddr>,
) -> Result<(), brake::Braked> {
    if !brake::needs_token(&head.method, path) {
        return Ok(());
    }
    let who = brake::Who::of(from);
    cfg.brake.held(who)?;
    let now = tokens::now_ms();
    let good = head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, now) || cfg.tokens.is_once(t, now));
    if !good {
        cfg.brake.strike(who);
    }
    Ok(())
}

/// The key that proved itself for a mint or a pair, whose share of the pairs
/// counts it (T-630); none where the role asks for no key.
type Maker = Option<crate::identity::PublicKey>;

/// Whether a mint or a pair of `body` may go on, by whom the role mints for:
/// `Ok` holds the key that proved itself, `Err` the answer, a `401` that asks
/// for a key or a `403`.
fn proven(cfg: &Config, head: &request::Request, sni: Option<&str>, path: &str, body: &[u8]) -> Result<Maker, Vec<u8>> {
    let Some(whom) = keys::Whom::of(&cfg.mint) else { return Ok(None) };
    match keys::prove(cfg, &whom, head, sni, path, body, tokens::now_ms()) {
        keys::Proof::Key(key, member) => {
            // A member of the net by its name too (T-455), for the owner.
            let member = member.map(|words| format!(", {words}")).unwrap_or_default();
            cfg.event(&format!("{path}: the key {}{member}", key.fingerprint()));
            Ok(Some(key))
        }
        keys::Proof::Ask(challenge, ends) => Err(keys::ask(&challenge, ends)),
        keys::Proof::Refused(why) => {
            cfg.event(&format!("{path}: refused, {why}"));
            Err(request::refusal(403, &format!("{path}: {why}"), &[]))
        }
    }
}

/// The body of a request, `max` bytes at most; `Err` holds the refusal to
/// answer, empty for a client that went away.
pub(super) async fn body<S>(
    stream: &mut S,
    head: &request::Request,
    mut pending: Vec<u8>,
    max: usize,
    path: &str,
) -> Result<Vec<u8>, Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let length: usize = head.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    if length > max {
        return Err(request::refusal(413, &format!("{path}: a body of {max} bytes at most"), &[]));
    }
    let mut chunk = [0u8; 1024];
    while pending.len() < length {
        match tokio::time::timeout(HEAD_WAIT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&chunk[..n]),
            _ => return Err(Vec::new()),
        }
    }
    pending.truncate(length);
    Ok(pending)
}

/// Write `reply`, then end the connection.
pub(super) async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) {
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}
