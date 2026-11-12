//! connect-ip over HTTP/3, sans-IO: the client's SETTINGS, the server's
//! SETTINGS read, the extended CONNECT's field section (RFC 9220 with
//! QPACK's static table alone, as Hysteria 2's request is written), the
//! HTTP Datagrams of IP packets (RFC 9297, section 2.1: a Quarter Stream ID,
//! then RFC 9484's Context ID 0 and the whole packet), and the capsule
//! ADDRESS_ASSIGN (RFC 9484, section 4.7.1), which gives the client its
//! address where no record of a device does.
//!
//! The varints are QUIC's (RFC 9000, section 16), those of `crate::capsule`;
//! QPACK's integers and literals are podssh-ws's Hysteria code, shared.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use podssh_ws::hysteria::h3 as qpack;

use crate::capsule::{put_varint, read_varint};

/// The type of the control stream and of SETTINGS (RFC 9114, sections 6.2.1
/// and 7.2.4).
pub const CONTROL_STREAM: u64 = 0x00;
pub const SETTINGS: u64 = 0x04;
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220, section 3, from RFC 8441).
pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// SETTINGS_H3_DATAGRAM (RFC 9297, section 5.1).
pub const H3_DATAGRAM: u64 = 0x33;
/// The draft's SETTINGS_H3_DATAGRAM, which WARP's own client still sends and
/// usque sends beside the RFC's (`api/masque.go`, quiche's `frame.rs`).
pub const H3_DATAGRAM_DRAFT: u64 = 0x276;
/// The capsules of connect-ip (RFC 9484, section 4.7).
pub const ADDRESS_ASSIGN: u64 = 0x01;
/// The Context ID of a whole IP packet (RFC 9484, section 6).
pub const CONTEXT_IP: u64 = 0;
/// The protocol of the extended CONNECT: RFC 9484's, and WARP's edge's
/// (usque's `connectip.Dial(..., "cf-connect-ip", ...)`).
pub const CONNECT_IP: &str = "connect-ip";
pub const CF_CONNECT_IP: &str = "cf-connect-ip";

/// The client's control stream as it opens: its type, then SETTINGS with
/// HTTP Datagrams on, the draft's setting too for WARP's edge; no dynamic
/// table of QPACK, as each default holds.
pub fn control_stream(draft_datagram: bool) -> Vec<u8> {
    let mut settings = Vec::new();
    put_varint(&mut settings, H3_DATAGRAM);
    put_varint(&mut settings, 1);
    if draft_datagram {
        put_varint(&mut settings, H3_DATAGRAM_DRAFT);
        put_varint(&mut settings, 1);
    }
    let mut out = Vec::new();
    put_varint(&mut out, CONTROL_STREAM);
    out.extend_from_slice(&qpack::frame(SETTINGS, &settings));
    out
}

/// What the server's SETTINGS allow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Peer {
    /// HTTP Datagrams: the RFC's setting, or the draft's.
    pub datagrams: bool,
    /// The extended CONNECT. WARP's edge does not say it, and usque ignores
    /// that (`ignoreExtendedConnect`); a server of RFC 9484 says it.
    pub extended_connect: bool,
}

/// The payload of the server's SETTINGS frame, read; a setting that podssh
/// does not know is skipped (RFC 9114, section 7.2.4.1).
pub fn peer_settings(payload: &[u8]) -> Result<Peer, String> {
    let mut peer = Peer::default();
    let mut rest = payload;
    while !rest.is_empty() {
        let (id, a) = read_varint(rest).ok_or("the server's SETTINGS cut in an identifier")?;
        let (value, b) = read_varint(&rest[a..]).ok_or("the server's SETTINGS cut in a value")?;
        rest = &rest[a + b..];
        match id {
            H3_DATAGRAM | H3_DATAGRAM_DRAFT => peer.datagrams |= value == 1,
            ENABLE_CONNECT_PROTOCOL => peer.extended_connect = value == 1,
            _ => {}
        }
    }
    Ok(peer)
}

/// A field line with a name of QPACK's static table at `index` and a literal
/// value (RFC 9204, section 4.5.4: 01NT, T set, a 4-bit index).
pub fn static_name(out: &mut Vec<u8>, index: usize, value: &str) {
    qpack::put_int(out, 4, 0x50, index);
    qpack::put_literal(out, value.as_bytes());
}

/// A field line whose name and value are both literals (section 4.5.6:
/// 001N H and a 3-bit length), neither Huffman-coded.
pub fn literal_name(out: &mut Vec<u8>, name: &str, value: &str) {
    qpack::put_int(out, 3, 0x20, name.len());
    out.extend_from_slice(name.as_bytes());
    qpack::put_literal(out, value.as_bytes());
}

/// The field section of the extended CONNECT of `protocol` to `authority`
/// and `path`, as quic-go's request writer sends connect-ip-go's: `:method
/// CONNECT`, `:scheme https`, `:authority`, `:path`, `:protocol`, and
/// `capsule-protocol: ?1` (RFC 9297, section 3.4). No user-agent, as usque
/// sends none.
pub fn request(authority: &str, path: &str, protocol: &str) -> Vec<u8> {
    // The prefix: no insert count, base 0 (no dynamic table).
    let mut out = vec![0x00, 0x00];
    // Indexed, static (RFC 9204, appendix A): 15 is `:method CONNECT`, 23
    // `:scheme https`.
    out.extend_from_slice(&[0xc0 | 15, 0xc0 | 23]);
    // Static names: 0 is `:authority`, 1 `:path`.
    static_name(&mut out, 0, authority);
    static_name(&mut out, 1, path);
    literal_name(&mut out, ":protocol", protocol);
    literal_name(&mut out, "capsule-protocol", "?1");
    out
}

/// The HTTP Datagram of `packet` on the request stream `stream_id`.
pub fn datagram(stream_id: u64, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 10);
    put_varint(&mut out, stream_id / 4);
    put_varint(&mut out, CONTEXT_IP);
    out.extend_from_slice(packet);
    out
}

/// The bytes that [`datagram`] puts before a packet of `stream_id`.
pub fn overhead(stream_id: u64) -> usize {
    let mut out = Vec::new();
    put_varint(&mut out, stream_id / 4);
    put_varint(&mut out, CONTEXT_IP);
    out.len()
}

/// The IP packet of an HTTP Datagram of the request stream `stream_id`:
/// `None` for one of another stream or of another context, which is
/// dropped as connect-ip-go drops it; an error for one that is cut.
pub fn packet_of(stream_id: u64, datagram: &[u8]) -> Result<Option<&[u8]>, String> {
    let (quarter, a) = read_varint(datagram).ok_or("an HTTP Datagram cut in its Quarter Stream ID")?;
    let (context, b) = read_varint(&datagram[a..]).ok_or("an HTTP Datagram cut in its Context ID")?;
    if quarter != stream_id / 4 || context != CONTEXT_IP {
        return Ok(None);
    }
    Ok(Some(&datagram[a + b..]))
}

/// The addresses of an ADDRESS_ASSIGN capsule's payload, each with its
/// prefix's length.
pub fn assigned(payload: &[u8]) -> Result<Vec<(IpAddr, u8)>, String> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (_request, a) = read_varint(rest).ok_or("ADDRESS_ASSIGN cut in a Request ID")?;
        rest = &rest[a..];
        let (&version, after) = rest.split_first().ok_or("ADDRESS_ASSIGN cut before an IP Version")?;
        let len = match version {
            4 => 4,
            6 => 16,
            other => return Err(format!("ADDRESS_ASSIGN with the IP Version {other}")),
        };
        let (bytes, after) = (after.get(..len), after.get(len..));
        let (Some(bytes), Some(after)) = (bytes, after) else { return Err("ADDRESS_ASSIGN cut in an address".into()) };
        let (&prefix, after) = after.split_first().ok_or("ADDRESS_ASSIGN cut before a prefix length")?;
        if usize::from(prefix) > len * 8 {
            return Err(format!("ADDRESS_ASSIGN with a prefix of {prefix} bits for IPv{version}"));
        }
        let ip = match version {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).expect("four bytes"))),
            _ => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).expect("sixteen bytes"))),
        };
        out.push((ip, prefix));
        rest = after;
    }
    Ok(out)
}

/// The addresses that the stack takes from an assignment: the first of each
/// family.
pub fn stack_addresses(assigned: &[(IpAddr, u8)]) -> Vec<IpAddr> {
    let v4 = assigned.iter().map(|(ip, _)| *ip).find(IpAddr::is_ipv4);
    let v6 = assigned.iter().map(|(ip, _)| *ip).find(IpAddr::is_ipv6);
    v4.into_iter().chain(v6).collect()
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
