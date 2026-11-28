//! The credentials of Cloudflare Access on a WebSocket road that podssh
//! builds itself (T-718), beside `cf://` ([`crate::cloudflare`]): a host that
//! the user named for them gets the headers that cloudflared sends, and no
//! other host does, as a secret sent to a host of a pool or of a public
//! fallback would reach another party. The request is built in memory that
//! is wiped, and a refusal that quotes a value has it masked.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::cloudflare::{Access, CLIENT_ID, CLIENT_SECRET, TOKEN};
use crate::dial::ProxyChoice;
use crate::handshake;
use crate::session::RelaySession;
use crate::tls::Trust;
use crate::url::{self, Stream, WsUrl};

/// What a refusal shows in place of a credential that it quotes.
pub const MASK: &str = "<not shown>";

/// The hosts that the user named for the credentials, and the credentials.
#[derive(Clone, Default)]
pub struct Named {
    hosts: Vec<String>,
    access: Access,
}

impl fmt::Debug for Named {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Named").field("hosts", &self.hosts).field("access", &self.access).finish()
    }
}

/// The name of a host as a comparison takes it: lower case, no last dot,
/// an IPv6 address with no brackets.
pub fn host_key(host: &str) -> String {
    host.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase()
}

impl Named {
    /// `access` for each host of `hosts`.
    pub fn new(hosts: impl IntoIterator<Item = String>, access: Access) -> Named {
        let mut hosts: Vec<String> = hosts.into_iter().map(|h| host_key(&h)).filter(|h| !h.is_empty()).collect();
        hosts.sort();
        hosts.dedup();
        Named { hosts, access }
    }

    /// The hosts, as compared.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The credentials for `host`: none for a host that the user did not
    /// name, and none when no credential is set.
    pub fn for_host(&self, host: &str) -> Option<&Access> {
        let key = host_key(host);
        (!is_empty(&self.access) && self.hosts.contains(&key)).then_some(&self.access)
    }
}

/// The hosts and credentials of this process, which [`client::way`] gives
/// each road that pod-ws builds (pod-ws's `Headers`, podcrates `v0.68.0`):
/// none until the command line sets them.
static PROCESS: std::sync::Mutex<Option<&'static Named>> = std::sync::Mutex::new(None);

/// Set the hosts and credentials of this process: the settings' at the
/// start, then a command line's flags in their place. Each is kept for
/// the process's life (at most a few), as each road built before still
/// reads the one it took.
pub fn set_process(named: Named) {
    let named: &'static Named = Box::leak(Box::new(named));
    *PROCESS.lock().unwrap_or_else(|e| e.into_inner()) = Some(named);
}

/// The headers of each road of this process: the credentials for a host
/// that the user named, and nothing for any other host.
pub fn process_headers() -> pod_ws::Headers {
    let named = *PROCESS.lock().unwrap_or_else(|e| e.into_inner());
    match named.filter(|named| !named.hosts.is_empty() && !is_empty(&named.access)) {
        Some(named) => headers_of(named),
        None => pod_ws::Headers::default(),
    }
}

/// Whether this process sends Cloudflare Access credentials to `host`
/// (`AccessHost` in the settings, or `--access-host` on the command line).
pub fn process_names(host: &str) -> bool {
    let named = *PROCESS.lock().unwrap_or_else(|e| e.into_inner());
    named.is_some_and(|named| named.for_host(host).is_some())
}

/// The headers of `named` for each host that a road names.
fn headers_of(named: &'static Named) -> pod_ws::Headers {
    pod_ws::Headers::new(move |host: &str| {
        let Some(access) = named.for_host(host) else { return Vec::new() };
        headers(access).into_iter().map(|(name, value)| (name, Zeroizing::new(value.to_string()))).collect()
    })
}

/// Whether `access` holds no credential at all.
pub fn is_empty(access: &Access) -> bool {
    access.client_id.is_none() && access.client_secret.is_none() && access.token.is_none()
}

/// The headers of `access`, in the order of their names, as cloudflared
/// sends them: the service token whole, and the token of a user.
fn headers(access: &Access) -> Vec<(&'static str, &str)> {
    let mut headers = Vec::new();
    if let (Some(id), Some(secret)) = (&access.client_id, &access.client_secret) {
        headers.push((CLIENT_ID, id.as_str()));
        headers.push((CLIENT_SECRET, secret.as_str()));
    }
    if let Some(token) = &access.token {
        headers.push((TOKEN, token.as_str()));
    }
    headers
}

/// `request`, an upgrade whose head ends with its empty line, with the
/// headers of `access` before that line. A value with a control character
/// is refused; the refusal names the header, never the value.
pub fn splice(request: &[u8], access: &Access) -> Result<Zeroizing<Vec<u8>>, ConnectError> {
    let Some(head) = request.strip_suffix(b"\r\n") else {
        return Err(ConnectError::Config("the upgrade request has no end".into()));
    };
    if !head.ends_with(b"\r\n") {
        return Err(ConnectError::Config("the upgrade request has no end".into()));
    }
    let headers = headers(access);
    if let Some((name, _)) = headers.iter().find(|(_, v)| v.contains(|c: char| c.is_control())) {
        return Err(ConnectError::Config(format!("the value of {name} holds a control character")));
    }
    // Sized once, so that no copy of a credential is left in a freed buffer.
    let size = request.len() + headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(head);
    for (name, value) in &headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// `text` with each credential of `access` that it quotes masked: a far end
/// may echo what it was sent.
pub fn masked(text: String, access: &Access) -> String {
    headers(access).iter().map(|(_, v)| *v).filter(|v| !v.is_empty()).fold(text, |t, v| t.replace(v, MASK))
}

/// [`masked`] on each line that an error of the road holds.
pub fn masked_error(e: ConnectError, access: &Access) -> ConnectError {
    match e {
        ConnectError::Refused { status, body } => ConnectError::Refused { status, body: masked(body, access) },
        ConnectError::Upgrade(why) => ConnectError::Upgrade(masked(why, access)),
        ConnectError::Http(why) => ConnectError::Http(masked(why, access)),
        ConnectError::Config(why) => ConnectError::Config(masked(why, access)),
        other => other,
    }
}

/// Dial `url` and upgrade as [`url::dial`] does, with the headers of
/// `access` in the upgrade: the caller gives `access` only for a host that
/// the user named for it.
pub async fn dial(
    url: &WsUrl,
    access: &Access,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<Stream>, ConnectError> {
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = splice(&url::request(url, &key)?, access)?;
    let way = client::way(proxy);
    let stream = if url.tls {
        Stream::Tls(Box::new(way.open_tls(&url.host, url.port, &url.host, trust, timeout, &[]).await?.0))
    } else {
        Stream::Plain(way.tcp(&url.host, url.port, timeout).await.map_err(ConnectError::Dial)?.io)
    };
    let upgraded = tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await;
    let late = |_| ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout };
    let (stream, pending) = upgraded.map_err(late)?.map_err(|e| masked_error(e, access))?;
    Ok(RelaySession::new(stream, pending, idle, WRITE_TIMEOUT).naming("the server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(id: &str, secret: &str) -> Access {
        Access {
            client_id: Some(Zeroizing::new(id.into())),
            client_secret: Some(Zeroizing::new(secret.into())),
            token: None,
        }
    }

    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: edge.example\r\nSec-WebSocket-Version: 13\r\n\r\n";

    #[test]
    fn the_headers_go_before_the_empty_line_and_the_head_ends_once() {
        let out = splice(REQUEST, &service("id.access", "the-secret")).unwrap();
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\nHost: edge.example\r\n"), "{text}");
        let lines = "\r\nCf-Access-Client-Id: id.access\r\nCf-Access-Client-Secret: the-secret\r\n";
        assert!(text.contains(lines), "{text}");
        assert!(text.ends_with("\r\n\r\n") && !text[..text.len() - 4].contains("\r\n\r\n"), "one end: {text}");
        // No credential: the request as it was.
        assert_eq!(splice(REQUEST, &Access::default()).unwrap().as_slice(), REQUEST);
        assert!(splice(b"GET / HTTP/1.1\r\n", &Access::default()).is_err(), "a head with no end");
    }

    #[test]
    fn a_control_character_is_refused_by_the_header_s_name_alone() {
        let Err(ConnectError::Config(why)) = splice(REQUEST, &service("id", "sec\r\nX-Evil: 1")) else {
            panic!("a line break was spliced")
        };
        assert!(why.contains(CLIENT_SECRET) && !why.contains("sec") && !why.contains("Evil"), "{why}");
    }

    #[test]
    fn only_a_named_host_gets_the_credentials() {
        let named = Named::new(["Edge.Example.".to_string(), "[::1]".to_string()], service("id", "s"));
        assert!(named.for_host("edge.example").is_some());
        assert!(named.for_host("EDGE.example.").is_some());
        assert!(named.for_host("::1").is_some());
        for other in ["relay.example", "edge.example.evil", "example", ""] {
            assert!(named.for_host(other).is_none(), "{other}");
        }
        let unset = Named::new(["edge.example".to_string()], Access::default());
        assert!(unset.for_host("edge.example").is_none(), "no credential, no header");
        assert!(!format!("{named:?}").contains("\"s\""), "{named:?}");
    }

    #[test]
    fn each_road_gets_the_headers_for_a_named_host_alone() {
        let named: &'static Named = Box::leak(Box::new(Named::new(["edge.example".to_string()], service("id", "s"))));
        let headers = headers_of(named);
        let shown = format!("{:?}", headers.for_host("EDGE.example").unwrap());
        assert!(shown.contains(CLIENT_ID) && shown.contains(CLIENT_SECRET) && !shown.contains("\"s\""), "{shown}");
        let other = format!("{:?}", headers.for_host("relay.example").unwrap());
        assert!(!other.contains(CLIENT_ID), "{other}");
        assert!(format!("{:?}", headers.for_cleartext("edge.example").unwrap()).ends_with("([])"), "TLS alone");
    }

    /// The one test that sets the process's hosts: each way that
    /// `client::way` builds then gives the named host the headers alone.
    #[test]
    fn the_way_of_the_process_carries_the_hosts_that_were_set() {
        set_process(Named::new(["edge.example".to_string()], service("id", "s")));
        assert!(process_names("edge.example") && process_names("EDGE.example."));
        assert!(!process_names("relay.example"));
        let way = crate::client::way(&ProxyChoice::Direct);
        assert!(format!("{:?}", way.extra("edge.example").unwrap()).contains(CLIENT_ID));
        assert!(!format!("{:?}", way.extra("relay.example").unwrap()).contains(CLIENT_ID));
        set_process(Named::default());
        assert!(!process_names("edge.example"), "none set, none named");
        let way = crate::client::way(&ProxyChoice::Direct);
        assert!(!format!("{:?}", way.extra("edge.example").unwrap()).contains(CLIENT_ID), "none set, none sent");
    }

    #[test]
    fn a_refusal_that_quotes_a_credential_has_it_masked() {
        let access = service("id.access", "the-secret");
        let e = ConnectError::Refused { status: 403, body: "sent the-secret for id.access".into() };
        let ConnectError::Refused { body, .. } = masked_error(e, &access) else { panic!("not a refusal") };
        assert!(!body.contains("the-secret") && !body.contains("id.access") && body.contains(MASK), "{body}");
        let e = masked_error(ConnectError::Upgrade("a the-secret".into()), &access).to_string();
        assert!(!e.contains("the-secret"), "{e}");
    }
}
