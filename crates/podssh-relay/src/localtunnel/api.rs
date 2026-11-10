//! The request of a tunnel at a localtunnel server: one `GET` on a
//! connection of its own over podssh-ws's HTTP/1.1, as localtunnel's client
//! asks it (`lib/Tunnel.js`, `_init`): `/?new` for a random name, `/NAME`
//! for a name of the node's own. The answer is checked before it is used:
//! the id is one label, the port is one, the URL is `https://ID.` and a
//! domain, as each goes into a line, a name that a client dials, and the
//! node's connections.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use serde_json::Value;

use super::Service;
use crate::opentunnel::dial::{BoxIo, Dialing, CONNECT_LIMIT};

/// The largest answer read: the server's is a few dozen bytes.
pub const MAX_BODY: usize = 16 * 1024;
/// The bound of one request, its connection and its answer.
pub const REQUEST_LIMIT: Duration = Duration::from_secs(30);
/// The most connections that a node keeps: the server's own bound, 10
/// (`DEFAULT_MAX_SOCKETS` of `lib/TunnelAgent.js`), past which it closes
/// each new one.
pub const MOST_CONNECTIONS: usize = 10;

/// How a node reaches the API's host: [`tls`], or a test's stream.
pub type Dial = Arc<dyn Fn(&Service) -> Dialing + Send + Sync>;

/// A tunnel that the server gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    /// Its id, the first label of its name.
    pub id: String,
    /// The port of its connections at the server.
    pub port: u16,
    /// How many connections the node keeps there.
    pub connections: usize,
    /// Its name, `ID.` and the server's domain, with no port.
    pub host: String,
    /// The port of its name, 443 where the URL names none.
    pub web_port: u16,
    /// The address of its connections, where the server named one.
    pub ip: Option<IpAddr>,
}

impl Tunnel {
    /// The URL that a visitor opens.
    pub fn url(&self) -> String {
        match self.web_port {
            super::PORT => format!("https://{}", self.host),
            port => format!("https://{}", podssh_ws::dial::authority(&self.host, port)),
        }
    }

    /// Where its connections go: the address that the server named, as
    /// localtunnel's client prefers it, else the API's host.
    pub fn dial_host(&self, service: &Service) -> String {
        self.ip.map_or_else(|| service.host.clone(), |ip| ip.to_string())
    }
}

/// Why a request gave no tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The server answered no for this request: another will get the same.
    Refused(String),
    /// No answer, or one that a later try may change.
    ForNow(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Refused(why) | Failed::ForNow(why) => f.write_str(why),
        }
    }
}

/// TLS to the API's host through `proxy`, verified with `trust`; plain TCP,
/// directly, to a server of the loopback.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |service: &Service| -> Dialing {
        let (service, trust, proxy) = (service.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let host = service.host.as_str();
            if !service.tls {
                let tcp = podssh_ws::dial::dial(host, service.port, &ProxyChoice::Direct, CONNECT_LIMIT).await;
                return tcp.map(|tcp| Box::new(tcp) as BoxIo).map_err(|e| format!("{service}: {e}"));
            }
            let opened = podssh_ws::client::open_tls(host, service.port, host, &trust, &proxy, CONNECT_LIMIT);
            let tls = opened.await.map_err(|e| format!("{service}: {e}"))?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// The path of the request: the name `asked`, or a random one.
pub fn path(asked: Option<&str>) -> String {
    match asked {
        Some(name) => format!("/{name}"),
        None => "/?new".to_string(),
    }
}

/// Ask `service` for a tunnel, of the name `asked` where it is free.
pub async fn ask(service: &Service, dial: &Dial, asked: Option<&str>) -> Result<Tunnel, Failed> {
    let shown = service.shown();
    let mut io = match tokio::time::timeout(REQUEST_LIMIT, dial(service)).await {
        Err(_) => return Err(Failed::ForNow(format!("{shown}: no connection within {} s", REQUEST_LIMIT.as_secs()))),
        Ok(Err(why)) => return Err(Failed::ForNow(why)),
        Ok(Ok(io)) => io,
    };
    let headers = [("Accept", "application/json")];
    let (path, authority) = (path(asked), service.authority());
    let asking = podssh_ws::http::exchange(&mut io, "GET", &authority, &path, &headers, b"", MAX_BODY);
    let response = match tokio::time::timeout(REQUEST_LIMIT, asking).await {
        Err(_) => return Err(Failed::ForNow(format!("{shown}: no answer within {} s", REQUEST_LIMIT.as_secs()))),
        Ok(Err(e)) => return Err(Failed::ForNow(format!("{shown}: {e}"))),
        Ok(Ok(response)) => response,
    };
    let words = || message(&response.body);
    match response.status {
        200 => parse(&response.body).map_err(|why| Failed::ForNow(format!("{shown}: {why}"))),
        // The server's own words, as `_init` reads them: a bad name is 403.
        status @ 400..=499 => Err(Failed::Refused(format!("{shown} answered {status}: {}", words()))),
        status => Err(Failed::ForNow(format!("{shown} answered {status}: {}", words()))),
    }
}

/// The `message` of an answer's JSON, on one line, else its first words.
fn message(body: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let text = parsed.as_ref().and_then(|v| v.get("message")).and_then(Value::as_str).map(str::to_string);
    let text = text.unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    podssh_ws::text::one_line(&text).chars().take(200).collect()
}

/// The server's answer: `{id, port, max_conn_count, url}` and maybe `ip`.
pub fn parse(body: &[u8]) -> Result<Tunnel, String> {
    let value: Value = serde_json::from_slice(body).map_err(|_| "its answer is not JSON".to_string())?;
    let id = value.get("id").and_then(Value::as_str).filter(|id| super::is_label(id));
    let id = id.ok_or("its answer names no id that a name can hold")?.to_string();
    let port = value.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0);
    let port = port.ok_or("its answer names no port of the tunnel's connections")?;
    // As localtunnel's client: one connection where it names no count.
    let most = MOST_CONNECTIONS as u64;
    let connections = value.get("max_conn_count").and_then(Value::as_u64).unwrap_or(1).clamp(1, most) as usize;
    let url = value.get("url").and_then(Value::as_str).ok_or("its answer names no URL")?;
    let (host, web_port) = url_host(url).ok_or("its URL is not https://NAME")?;
    if !host.strip_prefix(id.as_str()).is_some_and(|rest| rest.starts_with('.') && rest.len() > 1) {
        return Err(format!("its URL {host} is not a name under the id {id}"));
    }
    let ip = value.get("ip").and_then(Value::as_str).and_then(|ip| ip.trim().parse().ok());
    Ok(Tunnel { id, port, connections, host, web_port, ip })
}

/// The host and the port of `https://HOST[:PORT][/]`, with no path or user.
fn url_host(url: &str) -> Option<(String, u16)> {
    let url = url.trim();
    if !url.get(..8)?.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &url[8..];
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = crate::pinggy::host_port(rest, "the localtunnel road").ok()?;
    host.contains('.').then_some((host, port.unwrap_or(super::PORT)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_of_localtunnel_s_server_gives_a_tunnel_and_a_bad_one_none() {
        // localtunnel/server's answer: `info` of `newClient` and its URL.
        let body = br#"{"id":"podssh-0011223344556677","port":38913,"max_conn_count":10,"url":"https://podssh-0011223344556677.loca.lt"}"#;
        let tunnel = parse(body).unwrap();
        assert_eq!((tunnel.port, tunnel.connections, tunnel.web_port), (38913, 10, 443));
        assert_eq!(tunnel.url(), "https://podssh-0011223344556677.loca.lt");
        let service = Service::parse("https://localtunnel.example.test").unwrap();
        assert_eq!(tunnel.dial_host(&service), "localtunnel.example.test", "no ip: the API's host");
        let with_ip = br#"{"id":"heavy-puma-9","port":1234,"max_conn_count":99,"url":"https://heavy-puma-9.lt.test:8443/","ip":"192.0.2.7"}"#;
        let tunnel = parse(with_ip).unwrap();
        assert_eq!((tunnel.connections, tunnel.web_port), (MOST_CONNECTIONS, 8443), "the server's own bound");
        assert_eq!(tunnel.dial_host(&service), "192.0.2.7");
        let no_count = br#"{"id":"abcd","port":9,"url":"https://abcd.lt.test"}"#;
        assert_eq!(parse(no_count).unwrap().connections, 1, "one, as localtunnel's client takes it");
        for bad in [
            &br#"{"id":"Bad Id","port":1,"url":"https://x.lt.test"}"#[..],
            br#"{"id":"abcd","port":0,"url":"https://abcd.lt.test"}"#,
            br#"{"id":"abcd","port":1,"url":"http://abcd.lt.test"}"#,
            br#"{"id":"abcd","port":1,"url":"https://other.lt.test"}"#,
            br#"{"id":"abcd","port":1,"url":"https://abcd.lt.test/path"}"#,
            b"not json",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_name_of_the_node_s_own_is_asked_by_its_path() {
        assert_eq!(path(None), "/?new");
        assert_eq!(path(Some("podssh-0011223344556677")), "/podssh-0011223344556677");
        assert_eq!(message(br#"{"message":"Invalid subdomain.\nAgain"}"#), "Invalid subdomain. Again");
    }
}
