//! A node's public ports at a bore server, and its hello, derived from its
//! key: the node asks the ports in their order, and a client that holds the
//! key derives the same, so no port passes between them. Each is of the
//! key's fingerprint, the text that podssh shows a key by (`SHA256:` and
//! base64), which `--node-key`, the net and the pins each give.
//!
//! The ports lie in bore's default range, 1024 to 65535 (`bore server`'s
//! `--min-port` and `--max-port`, `src/main.rs` at `00a735a89917`), as a
//! server takes a port that a node names only inside its range and when
//! nothing holds it (`create_listener` of `src/server.rs`): the node takes
//! the next where one is refused. The hello is the first bytes that the
//! node writes to each visitor, so that a client tells the node's port from
//! one that another tunnel holds; anyone can compute both from the public
//! key, so neither is a secret: the end-to-end channel is the check.

use sha2::{Digest, Sha256};

/// The context of the ports' hash: these ports are this road's alone.
const PORTS: &[u8] = b"podssh bore port v1\0";
/// The context of the hello's hash.
const HELLO: &[u8] = b"podssh bore hello v1\0";
/// The ports of a node's series.
pub const SERIES: usize = 4;
/// bore's default range of public ports.
pub const LOW: u16 = 1024;
pub const HIGH: u16 = 65535;
/// The bytes of the hello.
pub const HELLO_LEN: usize = 16;

/// The ports of the node whose key's fingerprint is `fingerprint`, in the
/// order that the node asks them and a client tries them: for each step
/// `k` from 0, the first four bytes of SHA-256 over the context, the
/// fingerprint and `k`, big-endian, into the range; a port that is the
/// control port, or one of the series already, is passed over.
pub fn of_fingerprint(fingerprint: &str) -> Vec<u16> {
    let span = u32::from(HIGH - LOW) + 1;
    let mut ports = Vec::with_capacity(SERIES);
    let mut k = 0u8;
    while ports.len() < SERIES {
        let digest = Sha256::new().chain_update(PORTS).chain_update(fingerprint.as_bytes()).chain_update([k]);
        let digest = digest.finalize();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let port = LOW + (n % span) as u16;
        if port != super::CONTROL_PORT && !ports.contains(&port) {
            ports.push(port);
        }
        k = k.wrapping_add(1);
    }
    ports
}

/// The hello of the node whose key's fingerprint is `fingerprint`: the
/// first [`HELLO_LEN`] bytes of SHA-256 over its context and the fingerprint.
pub fn hello(fingerprint: &str) -> [u8; HELLO_LEN] {
    let digest = Sha256::new().chain_update(HELLO).chain_update(fingerprint.as_bytes()).finalize();
    let mut hello = [0u8; HELLO_LEN];
    hello.copy_from_slice(&digest[..HELLO_LEN]);
    hello
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers, computed apart from this code (Python's hashlib, on
    /// 2026-11-10): a change of the derivation is a change of each node's
    /// ports, which its clients of another version would no longer find.
    #[test]
    fn the_ports_and_the_hello_are_of_the_key_s_fingerprint() {
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        assert_eq!(of_fingerprint(&fingerprint), vec![19390, 27632, 26232, 58364]);
        let other = format!("SHA256:{}", "B".repeat(43));
        assert_eq!(of_fingerprint(&other), vec![11252, 26712, 23559, 28959], "another key, other ports");
        let hex: String = hello(&fingerprint).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "53bf874cc9c5fe22402e17adeac2d2c5");
        assert_ne!(hello(&other), hello(&fingerprint));
    }

    #[test]
    fn each_port_is_in_bore_s_range_once_and_never_the_control_port() {
        for seed in 0..200u32 {
            let ports = of_fingerprint(&format!("SHA256:{seed:043}"));
            assert_eq!(ports.len(), SERIES);
            for (at, port) in ports.iter().enumerate() {
                assert!((LOW..=HIGH).contains(port) && *port != super::super::CONTROL_PORT, "{seed}: {port}");
                assert!(!ports[..at].contains(port), "{seed}: {port} twice");
            }
        }
    }
}
