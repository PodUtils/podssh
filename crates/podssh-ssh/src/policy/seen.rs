//! An observation of a server, from what the client's handshake record
//! kept and the host key that came: the glue between russh's types and the
//! pure verdict.

use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKeyOrCertificate;

use super::kexinit::{agreed, lists};
use super::verdict::{HostKeySeen, Observed, Side};
use super::Offers;

/// The server that `offers` and `key` show, judged from the client: its
/// lists in the direction it sends, and the key that came for the
/// algorithm that both KEXINITs agree on.
pub fn observe(offers: &Offers, key: &PublicKeyOrCertificate) -> Result<Observed, String> {
    let theirs = offers.theirs.as_deref().ok_or("the server's KEXINIT was not read whole")?;
    let ours = offers.ours.as_deref().ok_or("this side's KEXINIT was not read whole")?;
    let (theirs, ours) = (lists(theirs)?, lists(ours)?);
    let requested = agreed(&ours.host_keys, &theirs.host_keys)
        .ok_or("the two KEXINITs agree on no host key algorithm, yet a host key came")?;
    Ok(Observed {
        side: Side::Server,
        banner: offers.banner.clone(),
        header: offers.header.clone(),
        kex: theirs.kex,
        host_keys: theirs.host_keys,
        ciphers: theirs.ciphers_s2c,
        macs: theirs.macs_s2c,
        compressions: theirs.compression_s2c,
        host_key: Some(seen(requested, key)),
        dh_modulus: Default::default(),
    })
}

/// The key that came, by its own type, and its size measured on that type.
fn seen(requested: String, key: &PublicKeyOrCertificate) -> HostKeySeen {
    match key {
        PublicKeyOrCertificate::Certificate(cert) => {
            let signer = cert.signature_key();
            HostKeySeen {
                requested,
                returned: cert.public_key().algorithm().to_certificate_type(),
                bits: bits(cert.public_key()),
                ca: Some((signer.algorithm().as_str().to_string(), bits(signer))),
            }
        }
        PublicKeyOrCertificate::PublicKey { key, .. } => HostKeySeen {
            requested,
            returned: key.algorithm().as_str().to_string(),
            bits: bits(key.key_data()),
            ca: None,
        },
    }
}

/// A key's size in bits, as ssh-audit counts it: an RSA modulus, a curve's
/// field; 0 for a type that has none here.
fn bits(key: &KeyData) -> u32 {
    if let Some(rsa) = key.rsa() {
        return rsa.key_size();
    }
    match key.algorithm().as_str() {
        "ecdsa-sha2-nistp384" => 384,
        "ecdsa-sha2-nistp521" => 521,
        "ecdsa-sha2-nistp256" | "ssh-ed25519" | "sk-ecdsa-sha2-nistp256@openssh.com" | "sk-ssh-ed25519@openssh.com" => {
            256
        }
        // OpenSSH makes DSA keys of 1024 bits alone.
        "ssh-dss" => 1024,
        _ => 0,
    }
}
