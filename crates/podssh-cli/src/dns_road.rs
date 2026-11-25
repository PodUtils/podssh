//! What the DNS road (`--carrier dns:FILE`, T-877) and doctor's lines of it
//! (`doctor --dns-zone ZONE`, T-875) share: the resolver that the user names
//! or that `/etc/resolv.conf` lists, the probe of UDP that goes before any
//! datagram, and the bound of the owner's ruling Q107 (exception 11 of rule 2
//! of `AGENTS.md`): at most 20 queries a second and 8 in flight, nothing sent
//! unasked, and nothing sent where the probe found UDP refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The most queries a second that a run may send (Q107).
pub const MOST_RATE: f64 = 20.0;
/// The most queries that wait for their answer at once (Q107).
pub const MOST_IN_FLIGHT: usize = 8;
/// The port of a resolver that the user names with no port.
pub const PORT: u16 = 53;
/// Where Unix keeps the system's resolvers.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The most bytes of `/etc/resolv.conf` that are read: more is no such file.
const RESOLV_MOST: u64 = 64 * 1024;

/// The resolver that the queries go to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver {
    /// The address that the user named.
    Named(SocketAddr),
    /// The first `nameserver` of `/etc/resolv.conf`, read when the run starts.
    System,
}

impl Resolver {
    /// `system`, or an address: `IP`, `IP:PORT` or `[IPv6]:PORT`.
    pub fn parse(text: &str) -> Result<Resolver, String> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("system") {
            return Ok(Resolver::System);
        }
        address(text).map(Resolver::Named)
    }

    /// The address, and where it came from, for a line; the file read now
    /// for [`Resolver::System`].
    pub fn resolve(self, named_by: &str) -> Result<(SocketAddr, String), String> {
        match self {
            Resolver::Named(addr) => Ok((addr, format!("{addr}, from {named_by}"))),
            Resolver::System => {
                let addr = system()?;
                Ok((addr, format!("{addr}, the first nameserver of {RESOLV_CONF}")))
            }
        }
    }
}

/// A resolver's address: `IP` (port 53), `IP:PORT` or `[IPv6]:PORT`. A name
/// is refused: a name would need the resolver that this names.
pub fn address(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return check(addr, text);
    }
    if let Ok(ip) = text.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return check(SocketAddr::new(ip, PORT), text);
    }
    let shown = podssh_ws::text::one_line(&text.chars().take(64).collect::<String>());
    Err(format!("{shown} is no resolver's address: give IP, IP:PORT or [IPv6]:PORT"))
}

fn check(addr: SocketAddr, text: &str) -> Result<SocketAddr, String> {
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
        let shown = podssh_ws::text::one_line(text);
        return Err(format!("{shown} is no resolver's address: no port 0, no unspecified or multicast address"));
    }
    Ok(addr)
}

/// The first `nameserver` line of `text` (the form of `/etc/resolv.conf`)
/// whose address reads, at port 53. A link-local address with a zone
/// (`fe80::1%eth0`) does not read as an address here, and is passed over.
pub fn first_nameserver(text: &str) -> Option<SocketAddr> {
    text.lines()
        .map(|line| line.split(['#', ';']).next().unwrap_or_default())
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next()).flatten()
        })
        .filter_map(|word| word.parse::<IpAddr>().ok())
        .find(|ip| !ip.is_unspecified() && !ip.is_multicast())
        .map(|ip| SocketAddr::new(ip, PORT))
}

/// The first nameserver of `/etc/resolv.conf`, or why there is none.
pub fn system() -> Result<SocketAddr, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(RESOLV_CONF).map_err(|e| {
        format!(
            "{RESOLV_CONF}: {}; name the resolver (doctor --dns-server ADDR, or resolver = ADDR in FILE)",
            podssh_ws::text::said(&e)
        )
    })?;
    let mut text = String::new();
    file.take(RESOLV_MOST + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{RESOLV_CONF}: {}; name the resolver", podssh_ws::text::said(&e)))?;
    if text.len() as u64 > RESOLV_MOST {
        return Err(format!("{RESOLV_CONF} is over {RESOLV_MOST} bytes; name the resolver"));
    }
    first_nameserver(&text)
        .ok_or_else(|| format!("{RESOLV_CONF} names no nameserver that reads as an address; name the resolver"))
}

/// The probe of Q107 before any datagram: a UDP socket of this host, of the
/// resolver's family, connected to it. Connecting a UDP socket sends
/// nothing; a host that refuses UDP (`EPERM`, as the target sandbox does)
/// refuses here, and the run sends nothing.
pub fn udp_out(server: SocketAddr) -> Result<(), String> {
    let any: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let refused = |e: std::io::Error| {
        format!("UDP toward {server} is refused here ({}), so nothing was sent", podssh_ws::text::said(&e))
    };
    let socket = std::net::UdpSocket::bind(any).map_err(refused)?;
    socket.connect(server).map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One table: each form of a resolver's address, and each refusal.
    #[test]
    fn a_resolver_is_system_or_an_address_and_never_a_name() {
        let cases: &[(&str, Option<&str>)] = &[
            ("system", None),
            ("SYSTEM", None),
            ("192.0.2.1", Some("192.0.2.1:53")),
            ("192.0.2.1:5353", Some("192.0.2.1:5353")),
            ("2001:db8::1", Some("[2001:db8::1]:53")),
            ("[2001:db8::1]", Some("[2001:db8::1]:53")),
            ("[2001:db8::1]:5353", Some("[2001:db8::1]:5353")),
        ];
        for (text, want) in cases {
            let got = Resolver::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            match want {
                None => assert_eq!(got, Resolver::System, "{text}"),
                Some(addr) => assert_eq!(got, Resolver::Named(addr.parse().unwrap()), "{text}"),
            }
        }
        for bad in ["dns.example", "192.0.2.1:0", "0.0.0.0", "224.0.0.1", "", "1.2.3.4:99999", "a\u{1b}[2J"] {
            let why = Resolver::parse(bad).unwrap_err();
            assert!(why.contains("is no resolver's address"), "{bad:?}: {why}");
            assert!(!why.contains('\u{1b}'), "{why:?}");
        }
    }

    /// The first nameserver that reads, past comments, other lines, a
    /// zone's link-local address and the unspecified one.
    #[test]
    fn the_first_nameserver_that_reads_is_the_system_s() {
        let text = "# made by hand\nsearch example\noptions ndots:1\nnameserver fe80::1%eth0\nnameserver 0.0.0.0\n\
                    nameserver 127.0.0.53 # resolved\nnameserver 192.0.2.9\n";
        assert_eq!(first_nameserver(text), Some("127.0.0.53:53".parse().unwrap()));
        assert_eq!(first_nameserver("nameserver 2001:db8::53\n"), Some("[2001:db8::53]:53".parse().unwrap()));
        for none in ["", "search example\n", "#nameserver 192.0.2.1\n", "nameserver\n", "nameservers 192.0.2.1\n"] {
            assert_eq!(first_nameserver(none), None, "{none:?}");
        }
    }

    /// The probe sends nothing: a socket connected to a silent loopback
    /// port is no datagram, so the port reads none.
    #[test]
    fn the_probe_of_udp_sends_nothing() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        silent.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        udp_out(silent.local_addr().unwrap()).expect("UDP on the loopback");
        let mut byte = [0u8; 1];
        assert!(silent.recv_from(&mut byte).is_err(), "the probe sent a datagram");
    }
}
