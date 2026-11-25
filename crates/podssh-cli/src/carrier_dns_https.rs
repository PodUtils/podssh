//! `resolver = https://NAME[:PORT]/PATH` of `--carrier dns:FILE` (T-900):
//! the client's queries go as DNS over HTTPS (RFC 8484, a GET of the wire
//! form) to that resolver, over one connection through podssh's way out
//! (`HTTPS_PROXY` when it is set) and podssh's TLS, not as UDP datagrams. A
//! host whose only way out is an HTTP proxy has no UDP: this is its DNS road.
//! It is one outbound connection, so rule 2 of AGENTS.md needs no exception,
//! and no probe of UDP comes first. The codec is pod-link's
//! (`Dns::over_https`): a `429` of the resolver pauses the next query for its
//! `Retry-After`, and the ARQ sends the lost query again. The node's
//! listener is the same: the resolver passes the questions on as UDP.

use std::sync::Arc;
use std::time::Duration;

use pod_core::Dial;
use pod_link::dns::{Dns, DnsOverHttps};
use podssh_ws::dial::ProxyChoice;

/// The longest wait for the resolver's address, by podssh's own resolver.
const LOOKUP: Duration = Duration::from_secs(15);

/// A resolver of DNS over HTTPS that FILE names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Https {
    pub name: String,
    pub port: u16,
    /// The path of its wire form, as `/dns-query`.
    pub path: String,
}

impl std::fmt::Display for Https {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            443 => write!(f, "https://{}{}", self.name, self.path),
            port => write!(f, "https://{}:{port}{}", self.name, self.path),
        }
    }
}

/// `https://NAME[:PORT]/PATH`, or `None` when `text` is no `https://` URL.
pub(crate) fn parse(text: &str) -> Option<Result<Https, String>> {
    let text = text.trim();
    let scheme = "https://";
    if !text.get(..scheme.len()).is_some_and(|s| s.eq_ignore_ascii_case(scheme)) {
        return None;
    }
    Some(parse_url(&text[scheme.len()..]))
}

fn parse_url(rest: &str) -> Result<Https, String> {
    let shown = || podssh_ws::text::one_line(&rest.chars().take(64).collect::<String>());
    let wanted = "give https://NAME[:PORT]/PATH, as https://dns.example/dns-query";
    let Some((authority, path)) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))) else {
        return Err(format!("https://{}: no path of the wire form: {wanted}", shown()));
    };
    // The query is pod-link's (`?dns=`); a user name has no place here.
    if path == "/" || path.contains(['?', '#']) || authority.contains('@') {
        return Err(format!("https://{}: {wanted}", shown()));
    }
    if path.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err(format!("https://{}: the path has a space or a byte that is not ASCII", shown()));
    }
    let (name, port) =
        podssh_ws::dial::split_host_port(authority).map_err(|why| format!("https://{}: {why}", shown()))?;
    podssh_ws::dial::check_name(&name).map_err(|why| format!("https://{}: {why}", shown()))?;
    let port = match port {
        Some(0) => return Err(format!("https://{}: port 0", shown())),
        Some(port) => port,
        None => 443,
    };
    Ok(Https { name: name.to_ascii_lowercase(), port, path })
}

/// `dns` with its queries over DNS over HTTPS to `https`, through podssh's
/// way out of the environment. The resolver's address comes from podssh's
/// resolver (a pin of `PODSSH_RELAY_ADDR`, the system's, then podssh's own
/// DNS over HTTPS); the certificate must name NAME, under podssh's trust.
pub(crate) async fn carrier(dns: Dns, https: &Https) -> Result<Dns, String> {
    let deadline = tokio::time::Instant::now() + LOOKUP;
    let found = podssh_ws::resolve::resolve(&https.name, https.port, deadline)
        .await
        .map_err(|why| format!("the address of the resolver {https}: {why}"))?;
    let ip = found.first().ok_or_else(|| format!("the resolver {https} has no address"))?.ip();
    let doh = pod_dns::Doh::new(ip, https.name.clone()).port(https.port).wire(https.path.clone());
    let way: Arc<dyn Dial> = Arc::new(podssh_ws::dial::dialer(&ProxyChoice::FromEnvironment, false));
    let mut over = DnsOverHttps::new(doh, podssh_ws::tls::context().clone());
    // podssh's user agent, and its trust: SSL_CERT_FILE or the settings
    // file's CaFile replaces the roots, as for the relay.
    over.settings = podssh_ws::resolve::settings(Vec::new());
    over.settings.trust = crate::pairs::trust(None);
    Ok(dns.with_way(way).over_https(over))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of the words of `resolver`: what each gives.
    #[test]
    fn a_resolver_of_https_is_a_name_a_port_and_a_path() {
        let ok = |name: &str, port: u16, path: &str| Some(Ok(Https { name: name.into(), port, path: path.into() }));
        let cases: &[(&str, Option<Result<Https, String>>)] = &[
            ("https://dns.example/dns-query", ok("dns.example", 443, "/dns-query")),
            ("HTTPS://DNS.Example:8443/q", ok("dns.example", 8443, "/q")),
            ("  https://dns.example/a/b  ", ok("dns.example", 443, "/a/b")),
            ("system", None),
            ("1.1.1.1", None),
            ("http://dns.example/dns-query", None),
        ];
        for (text, want) in cases {
            assert_eq!(&parse(text), want, "{text}");
        }
        for bad in [
            "https://dns.example",
            "https://dns.example/",
            "https://dns.example/dns-query?dns=x",
            "https://user@dns.example/dns-query",
            "https://dns.example:0/dns-query",
            "https://dns.example:x/dns-query",
            "https:///dns-query",
            "https://dns.example/a b",
        ] {
            assert!(matches!(parse(bad), Some(Err(_))), "{bad}");
        }
    }

    #[test]
    fn the_url_is_said_back_with_its_port_only_when_not_443() {
        let https = |port| Https { name: "dns.example".into(), port, path: "/dns-query".into() };
        assert_eq!(https(443).to_string(), "https://dns.example/dns-query");
        assert_eq!(https(8443).to_string(), "https://dns.example:8443/dns-query");
    }
}
