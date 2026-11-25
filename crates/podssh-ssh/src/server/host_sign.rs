//! The host key's signature of each key exchange of `podssh serve` (T-856).
//! russh would sign with an RSA host key through the `rsa` crate, whose
//! private operation is open to a timing attack (RUSTSEC-2023-0071) that a
//! client of the server can run; so an RSA host key signs through aws-lc-rs,
//! as an RSA user key does (T-257, `rsa_key.rs`), and never through russh.
//! A host key sealed to a TPM (T-839) signs in the TPM, and never through
//! russh, which holds only its stand-in. Other Ed25519 and ECDSA keys stay
//! russh's to sign.

use std::sync::Arc;

use russh::keys::ssh_key;
use russh::keys::{HashAlg, PrivateKey};

use crate::rsa_key::RsaSigner;
use crate::tpm::host::{self, HostTpm};

/// The signer that the server's config hands to russh: one key, and its
/// aws-lc-rs key pair where it is RSA and aws-lc-rs took it, or its TPM.
pub(crate) struct HostSigner {
    rsa: Option<RsaSigner>,
    tpm: Option<Arc<HostTpm>>,
    stand_in: bool,
}

impl HostSigner {
    /// The signer of `key`. An RSA key that aws-lc-rs refuses gets none, and
    /// each exchange with it then fails: [`super::host_key::check`] refuses
    /// such a key before serve starts. So does a stand-in of a TPM's key
    /// that no TPM signs for.
    pub(crate) fn of(key: &PrivateKey) -> HostSigner {
        let rsa = if key.algorithm().is_rsa() { RsaSigner::of(key).ok() } else { None };
        HostSigner { rsa, tpm: host::of(key), stand_in: host::is_stand_in(key) }
    }
}

impl russh::server::HostKeySigner for HostSigner {
    fn sign(&self, key: &PrivateKey, hash: Option<HashAlg>, data: &[u8]) -> Option<Result<Vec<u8>, ssh_key::Error>> {
        // The TPM waits on the thread of the exchange: a second or so, each
        // command bounded, once for each key exchange.
        if let Some(tpm) = &self.tpm {
            return Some(tpm.sign(data).map_err(|why| {
                crate::err_line!("podssh serve: the TPM did not sign the key exchange: {why}");
                ssh_key::Error::Crypto
            }));
        }
        if self.stand_in {
            return Some(Err(ssh_key::Error::Crypto));
        }
        if !key.algorithm().is_rsa() {
            return None;
        }
        // Never russh's own signing for an RSA key: with no key pair of
        // aws-lc-rs, or for SHA-1 (`ssh-rsa`, out of the set), the exchange
        // fails.
        let Some(signer) = self.rsa.as_ref() else { return Some(Err(ssh_key::Error::Crypto)) };
        let (signed, name) = match hash {
            Some(HashAlg::Sha512) => (signer.sign_sha512(data), "rsa-sha2-512"),
            Some(HashAlg::Sha256) => (signer.sign_sha256(data), "rsa-sha2-256"),
            _ => return Some(Err(ssh_key::Error::Crypto)),
        };
        Some(signed.map(|signature| encoded(name, &signature)).map_err(|_| ssh_key::Error::Crypto))
    }
}

/// An SSH signature: the algorithm's name, then the signature, each a
/// string (RFC 4253, section 6.6; RFC 8332, section 3).
fn encoded(name: &str, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + name.len() + signature.len());
    for part in [name.as_bytes(), signature] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
#[path = "host_sign_tests.rs"]
mod tests;
