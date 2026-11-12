//! A server of connect-ip over HTTP/3 that the user runs (T-582's Approach,
//! step 4), by its URL: `https://HOST[:PORT][/PATH]`, its certificate
//! checked by the roots of podssh's trust, or pinned by the SHA-256 of its
//! DER as Hysteria's links pin one (podssh-ws's `hysteria::tls`, shared).
//! The CONNECT's `:authority` is the URL's host and port as written, as
//! connect-ip-go's server compares it with its template's; the server
//! assigns the address inside (ADDRESS_ASSIGN). The same code as WARP's
//! road over HTTP/3, with the protocol `connect-ip` of RFC 9484.

use std::net::SocketAddr;
use std::time::Duration;

use podssh_ws::hysteria::link::Check;
use podssh_ws::Trust;

use super::open::Ask;
use super::{Dial, Failed};

/// A server, as its URL names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// The host, bare (an IPv6 address with no brackets), for DNS and TLS.
    pub host: String,
    pub port: u16,
    /// The URL's host and port as written, for `:authority`.
    pub authority: String,
    pub path: String,
    /// The SHA-256 of the server's certificate, when it is pinned.
    pub pin: Option<[u8; 32]>,
    /// An address to dial in place of the host's, for a name that only the
    /// server's own network knows.
    pub at: Option<SocketAddr>,
}

/// Why a URL or a pin is not a server's.
fn bad(text: &str, why: &str) -> String {
    format!("{text}: {why}; a server of connect-ip over HTTP/3 is https://HOST[:PORT][/PATH]")
}

impl Server {
    /// The server of `url`, its certificate pinned by `pin` (64 hex digits,
    /// colons allowed) when one is given.
    pub fn parse(url: &str, pin: Option<&str>) -> Result<Server, String> {
        let rest = url.trim().strip_prefix("https://").ok_or_else(|| bad(url, "not an https:// URL"))?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') || path.contains('?') || path.contains('#') {
            return Err(bad(url, "a host with no user, and a path with no query"));
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or_else(|| bad(url, "an IPv6 address with no ]"))?;
                (host, after.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        if host.is_empty() || (!authority.starts_with('[') && host.contains(':')) {
            return Err(bad(url, "no host, or an IPv6 address with no brackets"));
        }
        let port = match port {
            None => 443,
            Some(p) => p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| bad(url, "a port of 1 to 65535"))?,
        };
        let pin = pin.map(parse_pin).transpose()?;
        let (host, authority, path) = (host.to_string(), authority.to_string(), path.to_string());
        Ok(Server { host, port, authority, path, pin, at: None })
    }

    /// The same server, dialled at `at`.
    pub fn at(mut self, at: SocketAddr) -> Server {
        self.at = Some(at);
        self
    }

    /// The server as the user named it, for the road's lines.
    pub fn shown(&self) -> String {
        format!("https://{}{}", self.authority, self.path)
    }

    /// The addresses to probe: `at`, else the host's, each within `limit`.
    pub async fn addresses(&self, limit: Duration) -> Result<Vec<SocketAddr>, Failed> {
        if let Some(at) = self.at {
            return Ok(vec![at]);
        }
        let deadline = tokio::time::Instant::now() + limit;
        podssh_ws::resolve::resolve(&self.host, self.port, deadline)
            .await
            .map_err(|e| Failed::Local(format!("{}: {e}", self.host)))
    }

    /// The dial of this server at `addr`, with `trust` where no pin is set;
    /// and the verifier of the pin, which says what it refused.
    pub fn dial(
        &self,
        addr: SocketAddr,
        trust: &Trust,
    ) -> Result<(Dial, Option<std::sync::Arc<podssh_ws::hysteria::tls::PinnedLeaf>>), Failed> {
        let check = match self.pin {
            Some(pin) => Check::Pin(pin),
            None => Check::Roots,
        };
        let (tls, pinned) = podssh_ws::hysteria::tls::config(&check, trust).map_err(Failed::Local)?;
        let ask = Ask {
            authority: self.authority.clone(),
            path: self.path.clone(),
            protocol: super::wire::CONNECT_IP,
            needs_extended_connect: true,
            draft_datagram: false,
        };
        Ok((Dial { addr, server_name: self.host.clone(), tls, ask, addresses: None }, pinned))
    }
}

/// A pin of 64 hex digits, colons allowed, as `openssl x509 -fingerprint
/// -sha256` prints one.
pub fn parse_pin(text: &str) -> Result<[u8; 32], String> {
    let digits: String = text.chars().filter(|c| *c != ':').collect();
    let refused = || format!("the pin {text}: the SHA-256 of the certificate, 64 hex digits");
    if digits.len() != 64 {
        return Err(refused());
    }
    let mut pin = [0u8; 32];
    for (i, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).map_err(|_| refused())?;
    }
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// connect-ip-go's integration proxy's template, `https://proxy:443/vpn`:
    /// its authority keeps the port, as Go's `url.Host` does.
    #[test]
    fn a_url_keeps_its_authority_as_written() {
        let s = Server::parse("https://proxy:443/vpn", None).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.authority.as_str(), s.path.as_str()), ("proxy", 443, "proxy:443", "/vpn"));
        let s = Server::parse("https://masque.example", None).unwrap();
        assert_eq!((s.port, s.authority.as_str(), s.path.as_str()), (443, "masque.example", "/"));
        let s = Server::parse("https://[2001:db8::1]:8443/.well-known/masque/ip/*/*/", None).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.authority.as_str()), ("2001:db8::1", 8443, "[2001:db8::1]:8443"));
        assert_eq!(s.shown(), "https://[2001:db8::1]:8443/.well-known/masque/ip/*/*/");
    }

    #[test]
    fn a_url_that_is_no_server_s_is_refused() {
        for url in ["http://proxy/vpn", "https://", "https://u@proxy/", "https://proxy:0/", "https://2001:db8::1/", "https://p/?q"] {
            assert!(Server::parse(url, None).is_err(), "{url}");
        }
    }

    /// The pin as openssl prints a fingerprint, colons and all.
    #[test]
    fn a_pin_reads_with_or_without_colons() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let pin = parse_pin(hex).unwrap();
        assert_eq!((pin[0], pin[31]), (0xe3, 0x55));
        let colons: Vec<String> = pin.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(parse_pin(&colons.join(":")).unwrap(), pin);
        assert!(parse_pin("e3b0").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
    }
}
