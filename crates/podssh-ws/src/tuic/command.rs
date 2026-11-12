//! TUIC's commands, version 5 (EAimTY/tuic `SPEC.md`): a version, a type and
//! its data, in network order. A client sends `Authenticate` on a
//! unidirectional stream, `Connect` at the front of a bidirectional stream
//! whose bytes follow it at once, and `Heartbeat` as a datagram; `Packet` and
//! `Dissociate` carry UDP, which this road does not.

use std::net::IpAddr;

use super::link::{Password, Uuid};

/// The version of the specification that podssh speaks.
pub const VERSION: u8 = 0x05;
/// The types of command (`SPEC.md`, "Command Types").
pub const AUTHENTICATE: u8 = 0x00;
pub const CONNECT: u8 = 0x01;
pub const HEARTBEAT: u8 = 0x04;

/// The types of `Address`: a name with its length first, IPv4, IPv6.
const NAME: u8 = 0x00;
const IPV4: u8 = 0x01;
const IPV6: u8 = 0x02;

/// The length of the token: 256 bits from the exporter.
pub const TOKEN_LEN: usize = 32;

/// `Heartbeat`, a whole datagram.
pub const HEARTBEAT_DATAGRAM: [u8; 2] = [VERSION, HEARTBEAT];

/// The token of `uuid` and `password` from the TLS keying material exporter
/// of the connection (RFC 5705): the UUID's 16 bytes as its label, the raw
/// password as its context, 32 bytes, as sing-box (`ExportKeyingMaterial(
/// string(uuid[:]), password, 32)`) and Itsusinn's tuic both derive it. The
/// exporter is the caller's, so that a test can see what it is asked.
pub fn token<E>(uuid: &Uuid, password: &Password, export: E) -> Result<[u8; TOKEN_LEN], String>
where
    E: FnOnce(&mut [u8], &[u8], &[u8]) -> Result<(), String>,
{
    let mut out = [0u8; TOKEN_LEN];
    export(&mut out, &uuid.0, password.bytes())?;
    Ok(out)
}

/// `Authenticate`: the version, the type, the UUID and the token, 50 bytes.
pub fn authenticate(uuid: &Uuid, token: &[u8; TOKEN_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + TOKEN_LEN);
    out.extend_from_slice(&[VERSION, AUTHENTICATE]);
    out.extend_from_slice(&uuid.0);
    out.extend_from_slice(token);
    out
}

/// `Connect` to `host:port`, or why the target cannot go in it.
pub fn connect(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut out = vec![VERSION, CONNECT];
    address(&mut out, host, port)?;
    Ok(out)
}

/// `Address` (`SPEC.md`, "Address"): an IP literal as its bytes, else a name
/// of 1 to 255 bytes, then the port.
fn address(out: &mut Vec<u8>, host: &str, port: u16) -> Result<(), String> {
    // A literal in brackets is an address, as a link writes IPv6.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(IPV6);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let len = u8::try_from(bare.len()).map_err(|_| "a name of more than 255 bytes")?;
            if len == 0 {
                return Err("an empty name".into());
            }
            out.push(NAME);
            out.push(len);
            out.extend_from_slice(bare.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] =
        [0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00];

    /// The byte layouts of `SPEC.md`, field by field.
    #[test]
    fn each_command_is_laid_out_as_the_specification_draws_it() {
        let token = [0xab; TOKEN_LEN];
        let auth = authenticate(&Uuid(UUID), &token);
        assert_eq!(auth.len(), 50);
        assert_eq!(auth[..2], [0x05, 0x00]);
        assert_eq!(auth[2..18], UUID);
        assert_eq!(auth[18..], token);
        let mut name = vec![0x05, 0x01, 0x00, 9];
        name.extend_from_slice(b"h.example");
        name.extend_from_slice(&[0, 22]);
        assert_eq!(connect("h.example", 22).unwrap(), name);
        assert_eq!(connect("192.0.2.7", 443).unwrap(), [0x05, 0x01, 0x01, 192, 0, 2, 7, 0x01, 0xbb]);
        let v6 = connect("[2001:db8::1]", 2222).unwrap();
        assert_eq!(v6[..3], [0x05, 0x01, 0x02]);
        assert_eq!(v6[3..19], "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(v6[19..], [0x08, 0xae]);
        assert_eq!(HEARTBEAT_DATAGRAM, [0x05, 0x04]);
        assert!(connect(&"a".repeat(256), 1).unwrap_err().contains("255 bytes"));
        assert!(connect("", 1).unwrap_err().contains("empty"));
    }

    /// The exporter is asked for 32 bytes with the UUID's bytes as its
    /// label and the password as its context, never the other way round.
    #[test]
    fn the_token_asks_the_exporter_with_the_uuid_as_label_and_the_password_as_context() {
        let password = Password::new("hello");
        let mut asked = None;
        let token = token(&Uuid(UUID), &password, |out, label, context| {
            asked = Some((out.len(), label.to_vec(), context.to_vec()));
            out.fill(7);
            Ok(())
        })
        .unwrap();
        assert_eq!(token, [7; TOKEN_LEN]);
        assert_eq!(asked, Some((32, UUID.to_vec(), b"hello".to_vec())));
        let failed = super::token(&Uuid(UUID), &password, |_, _, _| Err("no exporter".into()));
        assert_eq!(failed.unwrap_err(), "no exporter");
    }
}
