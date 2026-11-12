//! TURN's TCP allocations (RFC 6062 over RFC 8656), to a TURN server that
//! the user runs (T-621, the operator's rulings Q66, Q93 and Q95): coturn
//! beside a server of calls dials the TCP target that its client names, so
//! a user's own TURN server on 443 is a road with no relay. Read in RFC 8656
//! (Allocate, Refresh, the long-term credential), RFC 6062 (Connect,
//! ConnectionBind, the 30 s that a server waits for a peer before its 447),
//! RFC 7065 (the `turn:` and `turns:` URIs) and RFC 5769 (the test vectors).
//!
//! RFC 6062 carries the bytes on a second connection to the same server,
//! bound by ConnectionBind, while the first, the control connection that
//! holds the allocation, stays open and is refreshed ([`keep`]). That is the
//! seventh exception of rule 2 of `AGENTS.md` (Q93): only with `--turn`.
//! Through `HTTPS_PROXY`, both are CONNECTs to the same name.

pub mod client;
pub mod keep;
pub mod msg;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::client::{self as ws_client, ConnectError};
use crate::dial::{self, ProxyChoice};
use crate::stun;
use crate::tls::Trust;
use crate::url::Stream;
use client::Auth;
use msg::{ALLOCATE, CONNECT, CONNECTION_BIND, CONNECTION_ID, LIFETIME, NONCE, REALM, REQUESTED_ADDRESS_FAMILY};
use msg::{REQUESTED_TRANSPORT, XOR_PEER_ADDRESS, XOR_RELAYED_ADDRESS};

pub use keep::{silent, TurnStream};

/// The other end, in the words of a failure.
pub const PEER: &str = "the TURN server";

/// The port of a server that names none: 443 for `turns:`, which a host
/// whose egress is HTTPS reaches (the entry's ruling), 3478 for `turn:`.
pub const TLS_PORT: u16 = 443;
pub const PLAIN_PORT: u16 = 3478;

/// The wait for a Connect's answer: a server tries its peer for at least
/// 30 s before it answers 447 (RFC 6062, 5.2).
pub const CONNECT_WAIT: Duration = Duration::from_secs(40);

/// Where a road says why its allocation ended, once the session runs.
pub type Note = Arc<dyn Fn(&str) + Send + Sync>;

/// A TURN server of RFC 7065: `turns:HOST[:PORT]` or `turn:HOST[:PORT]`,
/// with `?transport=tcp` at most, as the control connection is TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Server {
    pub fn parse(text: &str) -> Result<Server, String> {
        let text = text.trim();
        let (scheme, rest) = text.split_once(':').ok_or("a TURN server is turns:HOST[:PORT], or turn:HOST[:PORT]")?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "turns" => true,
            "turn" => false,
            _ => return Err(format!("{scheme}: is no TURN URI: give turns:HOST[:PORT], or turn:HOST[:PORT]")),
        };
        if rest.starts_with("//") {
            return Err(format!("a TURN URI has no // (RFC 7065): give {scheme}:HOST[:PORT]"));
        }
        let (authority, query) = rest.split_once('?').map_or((rest, None), |(a, q)| (a, Some(q)));
        match query.map(str::to_ascii_lowercase).as_deref() {
            None | Some("transport=tcp") => {}
            Some("transport=udp") => {
                return Err("?transport=udp is TURN over UDP, whose allocations carry no TCP: leave it out".into())
            }
            Some(_) => return Err("a TURN URI takes ?transport=tcp and nothing else".into()),
        }
        if authority.contains('@') {
            return Err("a TURN URI holds no credential: give it in --turn-auth-file".into());
        }
        let default = if tls { TLS_PORT } else { PLAIN_PORT };
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or("an IPv6 address with no ]")?;
                (host.to_string(), after.strip_prefix(':').map(port_of).transpose()?.unwrap_or(default))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), port_of(port)?),
                None => (authority.to_string(), default),
            },
        };
        dial::check_name(&host).map_err(|e| e.to_string())?;
        Ok(Server { tls, host, port })
    }

    /// `turns:HOST[:PORT]`, the port only when it is not the default.
    pub fn shown(&self) -> String {
        let scheme = if self.tls { "turns" } else { "turn" };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default = if self.tls { TLS_PORT } else { PLAIN_PORT };
        match self.port == default {
            true => format!("{scheme}:{host}"),
            false => format!("{scheme}:{host}:{}", self.port),
        }
    }

    /// Whether the server is this host, where `turn:` sends nothing over a
    /// network.
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost") || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

fn port_of(text: &str) -> Result<u16, String> {
    text.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("{text} is no port"))
}

/// The credential of the server: a user and a password, or coturn's
/// `static-auth-secret`, from which a user and a password of a day are
/// made. Never shown.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    Password { user: String, password: Zeroizing<String> },
    Secret(Zeroizing<String>),
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

impl Credentials {
    /// A file's text: one line `USER:PASSWORD`, split at its first `:`, or
    /// `auth-secret SECRET` for a server of `use-auth-secret`. `#` starts a
    /// comment line. A refusal names a line by its number, never its text.
    pub fn parse(text: &str) -> Result<Credentials, String> {
        let lines: Vec<(usize, &str)> = text
            .lines()
            .enumerate()
            .map(|(n, l)| (n + 1, l.trim()))
            .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let [(n, line)] = lines.as_slice() else {
            return Err("it holds one line: USER:PASSWORD, or auth-secret SECRET".into());
        };
        if line.chars().any(char::is_control) {
            return Err(format!("line {n}: it holds a control character"));
        }
        if let Some(secret) = line.strip_prefix("auth-secret").filter(|s| s.starts_with(char::is_whitespace)) {
            return Ok(Credentials::Secret(Zeroizing::new(secret.trim().to_string())));
        }
        match line.split_once(':') {
            Some((user, password)) if !user.is_empty() && !password.is_empty() => {
                Ok(Credentials::Password { user: user.to_string(), password: Zeroizing::new(password.to_string()) })
            }
            _ => Err(format!("line {n}: a line is USER:PASSWORD, or auth-secret SECRET")),
        }
    }

    /// The user and the password of a request now: a secret's for a day.
    pub fn pair(&self) -> (String, Zeroizing<String>) {
        match self {
            Credentials::Password { user, password } => (user.clone(), password.clone()),
            Credentials::Secret(secret) => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                let (user, password) = msg::rest_credential(secret.as_bytes(), now.as_secs() + 86_400);
                (user, Zeroizing::new(password))
            }
        }
    }
}

/// A credential goes over TLS, or to this host: over `turn:` elsewhere the
/// network would read the user and could replay the integrity.
pub fn check(server: &Server) -> Result<(), String> {
    if !server.tls && !server.is_loopback() {
        return Err(format!(
            "{} has no TLS, and the network would read the session's setup: give turns:",
            server.shown()
        ));
    }
    Ok(())
}

/// How a road reaches its server.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on each dial with its TLS, and on each answer but Connect's.
    pub timeout: Duration,
    /// Where the keeper says why the allocation ended.
    pub note: Note,
}

/// Why a server carried nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnError {
    /// The target cannot be named, or has no address.
    Target(String),
    /// TCP, the host's proxy, or TLS.
    Connect(ConnectError),
    /// A TCP allocation refused: 442 or 508, or a 400 of REQUESTED-TRANSPORT.
    NoTcp { code: u16, reason: String },
    /// The credential refused twice (401), or a 401 with no realm.
    Auth(String),
    /// The target refused by the server's policy (403).
    Forbidden(String),
    /// The server did not reach the target (447).
    Unreached(String),
    /// Another error of a step.
    Refused { step: &'static str, code: u16, reason: String },
    /// An answer that is not a TURN server's.
    Protocol(String),
    /// A step did not finish in time.
    Timeout { step: &'static str, after: Duration },
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnError::Target(why) | TurnError::Protocol(why) => f.write_str(why),
            TurnError::Connect(e) => write!(f, "{e}"),
            TurnError::NoTcp { code, reason } => {
                write!(f, "it refused a TCP allocation ({code} {reason}): the server offers no RFC 6062")
            }
            TurnError::Auth(why) => write!(f, "it refused the credential: {why}"),
            TurnError::Forbidden(why) => write!(f, "its policy refuses the target (403 {why})"),
            TurnError::Unreached(why) => write!(f, "it did not reach the target (447 {why})"),
            TurnError::Refused { step, code, reason } => write!(f, "it refused {step}: {code} {reason}"),
            TurnError::Timeout { step, after } => write!(f, "{step} had no answer in {} s", after.as_secs()),
        }
    }
}

impl TurnError {
    /// The line that says it, the server named as `shown`.
    pub fn line(&self, shown: &str) -> String {
        match self {
            TurnError::Connect(ConnectError::Tls(why)) => format!("TLS with {PEER} {shown} failed: {why}"),
            other => format!("{PEER} {shown}: {other}"),
        }
    }
}

/// An open road, with what `doctor` says of it.
pub struct Opened {
    pub stream: TurnStream,
    /// The server's SOFTWARE, where it says it.
    pub software: Option<String>,
    /// The allocation's relayed address and its lifetime in seconds.
    pub relayed: Option<SocketAddr>,
    pub lifetime: u32,
    /// The time of the Allocate (with its 401), and of Connect with the bind.
    pub allocate: Duration,
    pub connect: Duration,
}

/// A connection to `server`: TCP through the proxy that `dial` names, then
/// TLS for `turns:`, checked for the server's name.
async fn connect_to(server: &Server, dial: &Dial<'_>) -> Result<Stream, TurnError> {
    let (h, p) = (server.host.as_str(), server.port);
    if server.tls {
        let tls = ws_client::open_tls(h, p, h, dial.trust, dial.proxy, dial.timeout).await;
        return Ok(Stream::Tls(Box::new(tls.map_err(TurnError::Connect)?)));
    }
    let tcp = dial::dial(h, p, dial.proxy, dial.timeout).await;
    Ok(Stream::Plain(Box::new(tcp.map_err(|e| TurnError::Connect(ConnectError::Dial(e)))?)))
}

/// The target's address: a Connect names an address, not a name, so the
/// name goes through podssh's own order of resolvers (`crate::resolve`),
/// as a host may have no resolver of its own. IPv4 first: an allocation is
/// IPv4 unless asked, and a server's relays are mostly IPv4.
async fn target_address(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr, TurnError> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    dial::check_name(host).map_err(|e| TurnError::Target(e.to_string()))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let found = crate::resolve::resolve(host, port, deadline).await.map_err(TurnError::Target)?;
    let first = found.iter().find(|a| a.is_ipv4()).or(found.first());
    first.copied().ok_or_else(|| TurnError::Target(format!("{host} has no address")))
}

/// The road to `host:port` through `server`: Allocate with
/// REQUESTED-TRANSPORT TCP, the credential that its 401 asks, Connect to
/// the target's address, then ConnectionBind on a second connection, whose
/// bytes are then the target's.
pub async fn open(
    server: &Server,
    credentials: &Credentials,
    host: &str,
    port: u16,
    dial: &Dial<'_>,
) -> Result<Opened, TurnError> {
    let target = target_address(host, port, dial.timeout).await?;
    let started = Instant::now();
    let mut control = connect_to(server, dial).await?;
    let mut transport: Vec<(u16, &[u8])> = Vec::new();
    let tcp = msg::requested_tcp();
    let v6 = msg::family_v6();
    transport.push((REQUESTED_TRANSPORT, &tcp));
    if target.is_ipv6() {
        transport.push((REQUESTED_ADDRESS_FAMILY, &v6));
    }
    // The first Allocate carries no credential: its 401 names the realm
    // and the nonce (RFC 8656, 7.2).
    let id = client::transaction_id()?;
    let first = stun::message(ALLOCATE, &id, &transport);
    let first = client::exchange(&mut control, &first, dial.timeout, "the Allocate").await?;
    let mut auth = match (first.is_success(), first.error().0) {
        (true, _) => {
            return Err(TurnError::Protocol("it allocated with no credential, which no TURN server does".into()))
        }
        (false, 401) => match (first.attribute(REALM), first.attribute(NONCE)) {
            (Some(realm), Some(nonce)) => Auth::of(credentials, &realm, &nonce),
            _ => return Err(TurnError::Auth("its 401 named no realm or no nonce".into())),
        },
        (false, _) => return Err(refused(&first, "the Allocate")),
    };
    let allocated = client::signed(&mut control, &mut auth, ALLOCATE, &transport, dial.timeout, "the Allocate").await?;
    if !allocated.is_success() {
        return Err(refused(&allocated, "the Allocate"));
    }
    let lifetime = allocated.attribute(LIFETIME).and_then(|v| msg::u32_of(&v)).unwrap_or(600);
    let answered = allocated.message().id;
    let relayed = allocated.attribute(XOR_RELAYED_ADDRESS).and_then(|v| stun::read_address(&v, Some(&answered)).ok());
    let software = first.software().or_else(|| allocated.software());
    let allocate = started.elapsed();

    let started = Instant::now();
    let id = client::transaction_id()?;
    let peer = stun::write_address(target, Some(&id));
    let connect = connect_request(&mut control, &mut auth, id, &peer).await?;
    if !connect.is_success() {
        return Err(refused(&connect, "the Connect"));
    }
    let Some(connection) = connect.attribute(CONNECTION_ID).filter(|v| v.len() == 4) else {
        return Err(TurnError::Protocol("its Connect's success named no CONNECTION-ID".into()));
    };
    // The second connection that RFC 6062 needs, to the same server (Q93).
    let mut data = connect_to(server, dial).await?;
    let attrs = [(CONNECTION_ID, connection.as_slice())];
    let bound =
        client::signed(&mut data, &mut auth, CONNECTION_BIND, &attrs, dial.timeout, "the ConnectionBind").await?;
    if !bound.is_success() {
        return Err(refused(&bound, "the ConnectionBind"));
    }
    let connect = started.elapsed();
    let stream = keep::keep(control, data, auth, lifetime, dial.note.clone());
    Ok(Opened { stream, software, relayed, lifetime, allocate, connect })
}

/// The Connect, signed by hand as its XOR-PEER-ADDRESS is XORed with the
/// transaction's own id; a stale nonce tried again with a new id.
async fn connect_request(
    control: &mut Stream,
    auth: &mut Auth,
    id: stun::TransactionId,
    peer: &[u8],
) -> Result<client::Answer, TurnError> {
    let request = auth.sign(CONNECT, &id, &[(XOR_PEER_ADDRESS, peer)]);
    let answer = client::exchange(control, &request, CONNECT_WAIT, "the Connect").await?;
    let answer = client::checked(answer, &auth.key[..])?;
    if answer.is_success() || answer.error().0 != 438 {
        return Ok(answer);
    }
    let Some(nonce) = answer.attribute(NONCE) else { return Ok(answer) };
    auth.nonce = nonce;
    let address = stun::read_address(peer, Some(&id)).map_err(TurnError::Protocol)?;
    let id = client::transaction_id()?;
    let peer = stun::write_address(address, Some(&id));
    let request = auth.sign(CONNECT, &id, &[(XOR_PEER_ADDRESS, &peer)]);
    let answer = client::exchange(control, &request, CONNECT_WAIT, "the Connect").await?;
    client::checked(answer, &auth.key[..])
}

/// The error of an answer, in the words of step 5 of T-621.
fn refused(answer: &client::Answer, step: &'static str) -> TurnError {
    let (code, reason) = answer.error();
    match code {
        401 => TurnError::Auth(format!("401 {reason}")),
        442 | 508 => TurnError::NoTcp { code, reason },
        // coturn answers a REQUESTED-TRANSPORT that it does not serve with
        // 400 on some builds: still no TCP allocation.
        400 if step == "the Allocate" => TurnError::NoTcp { code, reason },
        403 => TurnError::Forbidden(reason),
        447 => TurnError::Unreached(reason),
        _ => TurnError::Refused { step, code, reason },
    }
}

#[cfg(test)]
mod tests;
