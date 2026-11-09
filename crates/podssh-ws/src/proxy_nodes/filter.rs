//! The filters of Q79 at run time (T-574, Q90): a list's nodes change within
//! hours and no person screens them, so each node is judged by its own
//! words. A node is kept when it is on 443 with TLS, and either its address
//! is a public IP literal, or its host, its SNI and its `Host` are one name;
//! a node whose SNI or `Host` is another party's name fronts it and is
//! skipped, and so is a name under a suffix of a school, a church or a
//! government, which looks taken over. An address in a private range is no
//! node: a list must not point podssh at the user's own network. The tests
//! hold the rules; they are not a screen of the lists, which no code can be.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::Node;

/// The port of a kept node: HTTPS's, which a proxy that lets only HTTPS out
/// passes.
pub const PORT: u16 = 443;

/// The labels of a name that mark a school, a church or a government. A
/// label counts after the first one (`gov.example.com` is a company's), or
/// as the last one (`example.edu`).
pub const INSTITUTIONAL: &[&str] =
    &["edu", "k12", "ac", "sch", "school", "gov", "gob", "gouv", "mil", "church", "diocese", "parish"];

/// Why a node is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Skip {
    /// Not on 443.
    Port,
    /// No TLS: a proxy would read it, and a name cannot be checked.
    NoTls,
    /// An address of a private, loopback, link-local or reserved range.
    Private,
    /// Its SNI or `Host` is another name than its host.
    Fronts,
    /// Under a suffix of a school, a church or a government.
    Institution,
}

impl Skip {
    /// The words of a count's line.
    pub fn words(self) -> &'static str {
        match self {
            Skip::Port => "not on port 443",
            Skip::NoTls => "no TLS",
            Skip::Private => "an address of a private range",
            Skip::Fronts => "an SNI or a Host that is another name than the host",
            Skip::Institution => "a name under a school's, a church's or a government's suffix",
        }
    }
}

/// Whether `node` is kept, or why not.
pub fn judge(node: &Node) -> Result<(), Skip> {
    let (host, port) = node.address();
    if port != PORT {
        return Err(Skip::Port);
    }
    if !node.tls() {
        return Err(Skip::NoTls);
    }
    let (sni, authority) = node.names();
    let (host, sni, http) = (bare(host), bare(sni), http_name(authority));
    let named: Vec<String> = match host.parse::<IpAddr>() {
        Ok(ip) if !public(ip) => return Err(Skip::Private),
        // An address that a name fronts: the SNI and the Host are one name,
        // or are the address itself.
        Ok(_) => {
            let names: Vec<String> = [sni, http].into_iter().filter(|n| n.parse::<IpAddr>().is_err()).collect();
            if names.windows(2).any(|w| w[0] != w[1]) {
                return Err(Skip::Fronts);
            }
            names
        }
        Err(_) => {
            if sni != host || http != host {
                return Err(Skip::Fronts);
            }
            vec![host]
        }
    };
    match named.iter().any(|name| institutional(name)) {
        true => Err(Skip::Institution),
        false => Ok(()),
    }
}

/// A name in lower case, no brackets, no last dot.
fn bare(name: &str) -> String {
    name.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase()
}

/// The name of an HTTP `Host`, with no port, in lower case.
fn http_name(authority: &str) -> String {
    let name = match crate::dial::split_host_port(authority) {
        Ok((host, _)) => host,
        Err(_) => authority.to_string(),
    };
    bare(&name)
}

/// Whether `name` is under a suffix of an institution.
pub fn institutional(name: &str) -> bool {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    labels.iter().skip(1).any(|l| INSTITUTIONAL.contains(&l.to_ascii_lowercase().as_str()))
}

/// Whether `ip` is an address that a stranger may own: not private, not
/// loopback, not link-local, not shared, not documentation, not multicast.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (64..128).contains(&b);
    let benchmark = a == 198 && (b == 18 || b == 19);
    let reserved = a >= 240;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || shared
        || benchmark
        || reserved
        || a == 0)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let first = ip.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    let documentation = first == 0x2001 && ip.segments()[1] == 0x0db8;
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || unique_local || link_local || documentation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::Server;

    // Built from its parts: a scanner of secrets takes a whole link with an
    // ID for a credential.
    fn node(rest: &str) -> Node {
        let link = ["vless://550e8400-e29b-41d4", "-a716-446655440000@", rest].concat();
        Node::Vless(Server::parse(&link).unwrap())
    }

    #[test]
    fn a_node_of_one_name_on_443_with_tls_is_kept() {
        assert_eq!(judge(&node("n.example.com:443?type=ws&security=tls")), Ok(()));
        assert_eq!(judge(&node("n.example.com:443?type=ws&security=tls&sni=N.Example.com&host=n.example.com")), Ok(()));
        assert_eq!(judge(&node("N.Example.com:443?type=xhttp&security=tls")), Ok(()));
    }

    #[test]
    fn a_node_that_fronts_another_name_is_skipped() {
        let by_sni = node("n.example.com:443?type=ws&security=tls&sni=victim.example.org");
        assert_eq!(judge(&by_sni), Err(Skip::Fronts));
        let by_host = node("n.example.com:443?type=ws&security=tls&host=victim.example.org");
        assert_eq!(judge(&by_host), Err(Skip::Fronts));
        // An address with two different names fronts too; with one name, or
        // with none, it does not.
        let two = node("203.0.113.9:443?type=ws&security=tls&sni=a.example.com&host=b.example.com");
        assert_eq!(judge(&two), Err(Skip::Private), "203.0.113.0/24 is documentation");
        let two = node("8.8.4.4:443?type=ws&security=tls&sni=a.example.com&host=b.example.com");
        assert_eq!(judge(&two), Err(Skip::Fronts));
        assert_eq!(judge(&node("8.8.4.4:443?type=ws&security=tls&sni=a.example.com&host=a.example.com")), Ok(()));
        assert_eq!(judge(&node("8.8.4.4:443?type=ws&security=tls")), Ok(()));
    }

    #[test]
    fn a_node_under_an_institution_s_suffix_is_skipped() {
        for host in ["vpn.state.edu", "x.school.k12.ca.us", "a.ox.ac.uk", "b.city.gov", "c.agency.gov.br", "d.base.mil"]
        {
            assert_eq!(judge(&node(&format!("{host}:443?type=ws&security=tls"))), Err(Skip::Institution), "{host}");
        }
        for host in ["gov.example.com", "edu.example.net", "ac.example.io"] {
            assert_eq!(judge(&node(&format!("{host}:443?type=ws&security=tls"))), Ok(()), "{host}");
        }
        // An IP that a school's name fronts is skipped as well.
        let ip = node("8.8.4.4:443?type=ws&security=tls&sni=vpn.state.edu&host=vpn.state.edu");
        assert_eq!(judge(&ip), Err(Skip::Institution));
    }

    #[test]
    fn a_port_other_than_443_no_tls_and_a_private_address_are_skipped() {
        assert_eq!(judge(&node("n.example.com:8443?type=ws&security=tls")), Err(Skip::Port));
        assert_eq!(judge(&node("n.example.com:443?type=ws")), Err(Skip::NoTls));
        for ip in ["10.1.2.3", "127.0.0.1", "192.168.0.9", "172.16.0.1", "169.254.1.1", "100.64.0.1"] {
            assert_eq!(judge(&node(&format!("{ip}:443?type=ws&security=tls"))), Err(Skip::Private), "{ip}");
        }
    }

    #[test]
    fn an_address_of_a_private_range_is_no_public_address() {
        for ip in ["::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "2001:db8::1", "ff02::1"] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.4.4", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }
}
