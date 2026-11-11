//! ZeroTier's road of a podssh pair (T-733): both ends make what they need
//! from the pair's name and its connect token, which both hold and nobody
//! else does, with no word between them and no change of the pairing: the
//! node's identity (so a client knows the node's address), and an ad-hoc
//! network of one port of the pair's own. A client joins with an identity
//! made for its run. Who knows the token could make the node's identity
//! too, and so could hold its address; the end-to-end channel above the
//! road checks the node's own key, so such a one gets no session, only the
//! road's loss.

use sha2::{Digest, Sha512};

use crate::ffi;

/// The label of the derivation, which a new form of the road changes.
const LABEL: &[u8] = b"podssh zerotier pair road v1";

/// What both ends of a pair make.
#[derive(Clone)]
pub struct PairRoad {
    /// The ad-hoc network of `port` alone: `ff`, the port twice, `000000`.
    pub nwid: u64,
    /// The node's TCP port inside it.
    pub port: u16,
    /// The node's address, 40 bits.
    pub node: u64,
    /// The planet of both ends: `None`, the core's own (ZeroTier Inc.'s
    /// roots); a test's own world otherwise.
    pub planet: Option<Vec<u8>>,
    /// The node's secret identity, as the core keeps it.
    node_identity: String,
}

impl std::fmt::Debug for PairRoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the identity's secret.
        write!(f, "PairRoad {{ nwid: {:016x}, port: {}, node: {:010x} }}", self.nwid, self.port, self.node)
    }
}

impl PairRoad {
    /// The road of the pair `name` with the connect token `token`. It takes
    /// the time of an identity's memory-hard hash: a fraction of a second.
    pub fn of(name: &str, token: &str) -> Result<PairRoad, String> {
        let mut hash = Sha512::new();
        for part in [LABEL, name.as_bytes(), token.as_bytes()] {
            hash.update((part.len() as u32).to_be_bytes());
            hash.update(part);
        }
        let seed: [u8; 64] = hash.finalize().into();
        let port = port_of(&seed);
        let node_identity = identity_of_seed(&seed)?;
        let node = address_of_identity(&node_identity)?;
        Ok(PairRoad { nwid: adhoc(port), port, node, planet: None, node_identity })
    }

    /// The node's secret identity, for the node's own member alone.
    pub fn node_identity(&self) -> &str {
        &self.node_identity
    }
}

/// The ad-hoc network of the one port `port` (`Network.cpp`: `ff`, the first
/// port, the last, then zeroes).
pub fn adhoc(port: u16) -> u64 {
    (0xffu64 << 56) | (u64::from(port) << 40) | (u64::from(port) << 24)
}

/// A port of 1024 to 65,535, from the seed's last bytes, which the identity
/// does not take whole.
fn port_of(seed: &[u8; 64]) -> u16 {
    let n = u16::from_be_bytes([seed[62], seed[63]]);
    1024 + n % (u16::MAX - 1024 + 1)
}

/// The secret identity, as text, of `seed`: the same on each host.
pub fn identity_of_seed(seed: &[u8; 64]) -> Result<String, String> {
    let mut out = vec![0u8; 512];
    // Safety: `seed` holds 64 bytes, and `out` holds `cap` bytes.
    let len = unsafe { ffi::podssh_zt_identity_of_seed(seed.as_ptr(), out.as_mut_ptr().cast(), out.len() as u32) };
    if len < 0 {
        return Err("ZeroTier's core made no identity of the seed".into());
    }
    out.truncate(len as usize);
    String::from_utf8(out).map_err(|_| "the core's identity is not text".into())
}

/// The address of an identity's text: its first field, 10 hex digits.
pub fn address_of_identity(text: &str) -> Result<u64, String> {
    let field = text.split(':').next().unwrap_or_default();
    match field.len() {
        10 => u64::from_str_radix(field, 16).map_err(|_| "an identity's address is not hex".into()),
        _ => Err("an identity's address is not 10 hex digits".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ends_make_the_same_road_and_another_pair_another() {
        let a = PairRoad::of("lab", "token-one").unwrap();
        let again = PairRoad::of("lab", "token-one").unwrap();
        assert_eq!((a.nwid, a.port, a.node), (again.nwid, again.port, again.node));
        assert_eq!(a.node_identity(), again.node_identity());
        let other = PairRoad::of("lab", "token-two").unwrap();
        assert_ne!(a.node, other.node);
        assert_eq!(a.nwid >> 56, 0xff);
        assert_eq!(a.nwid & 0xff_ffff, 0, "an ad-hoc network");
        assert_eq!((a.nwid >> 40) & 0xffff, u64::from(a.port));
        assert!(a.port >= 1024);
        // The secret is never in a debug line.
        let shown = format!("{a:?}");
        assert!(!shown.contains(a.node_identity().split(':').nth(3).unwrap()));
    }

    /// The core takes the identity made of the seed as its own, at the
    /// address that the client computed.
    #[tokio::test]
    async fn the_core_takes_the_node_s_identity_at_its_address() {
        use std::sync::{Arc, Mutex};
        let road = PairRoad::of("lab", "token-one").unwrap();
        let state =
            crate::member::State { identity: Some(road.node_identity().as_bytes().to_vec()), ..Default::default() };
        let (out, _sent) = tokio::sync::mpsc::channel(8);
        let (_send, inbound) = tokio::sync::mpsc::channel(8);
        let wire = crate::member::Wire { out, inbound };
        let member = crate::member::Member::start(Arc::new(Mutex::new(state)), wire, None).unwrap();
        assert_eq!(member.address, road.node);
    }

    #[test]
    fn an_address_is_read_from_an_identity_s_text() {
        assert_eq!(address_of_identity("8056c2e21c:0:ab:cd").unwrap(), 0x8056c2e21c);
        assert!(address_of_identity("8056c2e2:0:ab").is_err());
    }
}
