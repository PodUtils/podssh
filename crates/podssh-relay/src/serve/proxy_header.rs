//! The PROXY protocol's header (T-807), as a TCP balancer of the owner's
//! (haproxy, nginx's stream module) writes it before the client's first
//! byte: version 1, a line of text, and version 2, binary (haproxy's
//! `proxy-protocol.txt`). Behind such a balancer each connection comes from
//! the balancer, so the brake, the slots and the log would count each client
//! as one address. `--proxy-protocol RANGES` names the balancers: a
//! connection from one of them must begin with the header, whose source is
//! then the client; one from elsewhere that begins with a header is closed,
//! as anyone could write one and pass for any address.
//!
//! The header is read byte by byte up to its end, never past it, so the
//! client's first bytes stay in the socket for the peeks of the listener.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

use super::ranges::Range;

/// The signature of version 2.
pub const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// The longest line of version 1, its CRLF counted (the specification's
/// 107 bytes).
pub const V1_MAX: usize = 107;
/// The longest address block of version 2 read: the addresses of a UNIX
/// socket are 216 bytes; TLVs past them are read and dropped, up to this.
pub const V2_MAX: usize = 1024;

/// What a header said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// The client's address.
    Client(IpAddr),
    /// The balancer's own connection (`LOCAL`, `UNKNOWN`, or a family that
    /// is no IP): the peer stays the address.
    Own,
}

/// The balancers that the owner named.
#[derive(Debug, Clone, Default)]
pub struct Trusted(Vec<Range>);

impl Trusted {
    /// `RANGES` of `--proxy-protocol`: `ADDR/BITS` or an address, separated
    /// by commas, read as each flag of ranges is.
    pub fn parse(text: &str) -> Result<Trusted, String> {
        let ranges = super::ranges::list(text)?.into_iter().map(|(_, range)| range).collect::<Vec<_>>();
        if ranges.is_empty() {
            return Err("--proxy-protocol names no range".into());
        }
        Ok(Trusted(ranges))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `peer` is a balancer that the owner named.
    pub fn holds(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.0.iter().any(|range| range.contains(peer))
    }
}

/// The address of a connection of `peer`: from its header when `peer` is a
/// trusted balancer, else `peer` itself when it sent none. `Err` says why
/// the connection is closed. Each read waits `wait` at most in all.
pub async fn client_of(tcp: &mut TcpStream, peer: IpAddr, trusted: &Trusted, wait: Duration) -> Result<IpAddr, String> {
    if trusted.is_empty() {
        return Ok(peer);
    }
    if trusted.holds(peer) {
        let read = tokio::time::timeout(wait, read(tcp)).await.map_err(|_| "no PROXY header in time".to_string())?;
        return match read? {
            Said::Client(client) => Ok(client.to_canonical()),
            Said::Own => Ok(peer),
        };
    }
    if begins_header(tcp, wait).await {
        return Err(format!("a PROXY header from {peer}, which --proxy-protocol does not name"));
    }
    Ok(peer)
}

/// Whether the first bytes of `tcp` begin a header of either version,
/// peeked: a TLS record begins 0x16, an HTTP request with its method, and
/// an SSH client with `SSH-`, none of which can.
async fn begins_header(tcp: &TcpStream, wait: Duration) -> bool {
    let mut first = [0u8; 6];
    let Ok(Ok(n)) = tokio::time::timeout(wait, tcp.peek(&mut first)).await else { return false };
    let seen = &first[..n];
    !seen.is_empty() && (b"PROXY ".starts_with(seen) || V2_SIGNATURE.starts_with(seen))
}

/// The header at the start of `from`, read to its last byte and no further.
pub async fn read<R: AsyncRead + Unpin>(from: &mut R) -> Result<Said, String> {
    let mut first = [0u8; 1];
    from.read_exact(&mut first).await.map_err(|e| format!("the PROXY header: {}", podssh_ws::text::said(&e)))?;
    match first[0] {
        b'P' => v1(from).await,
        b'\r' => v2(from).await,
        _ => Err("a trusted balancer's connection begins with no PROXY header".into()),
    }
}

/// Version 1, after its `P`: `PROXY TCP4|TCP6|UNKNOWN SRC DST SPORT DPORT\r\n`.
async fn v1<R: AsyncRead + Unpin>(from: &mut R) -> Result<Said, String> {
    let mut line = vec![b'P'];
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX {
            return Err(format!("a PROXY line longer than {V1_MAX} bytes"));
        }
        from.read_exact(&mut byte).await.map_err(|e| format!("the PROXY line: {}", podssh_ws::text::said(&e)))?;
        line.push(byte[0]);
    }
    parse_v1(&line[..line.len() - 2])
}

/// The words of a line of version 1, its CRLF taken off.
pub fn parse_v1(line: &[u8]) -> Result<Said, String> {
    let text = std::str::from_utf8(line).map_err(|_| "a PROXY line that is not text".to_string())?;
    let words: Vec<&str> = text.split(' ').collect();
    match words.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(Said::Own),
        ["PROXY", family @ ("TCP4" | "TCP6"), source, destination, sport, dport] => {
            let parsed = |word: &str| word.parse::<IpAddr>().ok().filter(|ip| ip.is_ipv4() == (*family == "TCP4"));
            let ports =
                [sport, dport].iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok());
            match (parsed(source), parsed(destination)) {
                (Some(client), Some(_)) if ports => Ok(Said::Client(client)),
                _ => Err(format!("a PROXY line of addresses that are not {family}'s: {text:?}")),
            }
        }
        _ => Err(format!("not a PROXY line: {text:?}")),
    }
}

/// Version 2, after its first `\r`.
async fn v2<R: AsyncRead + Unpin>(from: &mut R) -> Result<Said, String> {
    let mut head = [0u8; 15];
    from.read_exact(&mut head).await.map_err(|e| format!("the PROXY header: {}", podssh_ws::text::said(&e)))?;
    if head[..11] != V2_SIGNATURE[1..] {
        return Err("a header that begins as PROXY's version 2 and is not".into());
    }
    let length = usize::from(u16::from_be_bytes([head[13], head[14]]));
    if length > V2_MAX {
        return Err(format!("a PROXY header of {length} bytes of addresses, past {V2_MAX}"));
    }
    let mut rest = vec![0u8; length];
    from.read_exact(&mut rest).await.map_err(|e| format!("the PROXY header: {}", podssh_ws::text::said(&e)))?;
    parse_v2(head[11], head[12], &rest)
}

/// A header of version 2 by its command byte, its family byte, and its
/// address block.
pub fn parse_v2(command: u8, family: u8, block: &[u8]) -> Result<Said, String> {
    if command >> 4 != 2 {
        return Err(format!("a PROXY header of version {}, not 2", command >> 4));
    }
    match command & 0x0f {
        0 => return Ok(Said::Own),
        1 => {}
        other => return Err(format!("a PROXY header of command {other}")),
    }
    match family >> 4 {
        // AF_INET: two addresses of 4 bytes, then two ports.
        1 if block.len() >= 12 => Ok(Said::Client(IpAddr::V4(Ipv4Addr::new(block[0], block[1], block[2], block[3])))),
        // AF_INET6: two of 16 bytes, then two ports.
        2 if block.len() >= 36 => {
            let mut source = [0u8; 16];
            source.copy_from_slice(&block[..16]);
            Ok(Said::Client(IpAddr::V6(Ipv6Addr::from(source))))
        }
        1 | 2 => Err("a PROXY header too short for its addresses".into()),
        // AF_UNSPEC and AF_UNIX: no address of a client on the internet.
        _ => Ok(Said::Own),
    }
}

#[cfg(test)]
#[path = "proxy_header_tests.rs"]
mod tests;
