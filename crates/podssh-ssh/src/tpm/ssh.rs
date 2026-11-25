//! The forms of SSH of a TPM key (T-839): the public key
//! `ecdsa-sha2-nistp256` of its point, and the signature of `TPM2_Sign` as
//! SSH carries it (the name, then `r` and `s` as mpints, RFC 5656). They
//! stay in podssh: `pod-tpm` takes no type of russh.

use pod_tpm::EcdsaSignature;
use russh::keys::PublicKey;

/// The SHA-256 of `data`: the digest that the TPM signs.
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// The key as SSH carries it, from the uncompressed point of P-256.
pub(super) fn public_key(point: &[u8; 65]) -> Result<PublicKey, String> {
    let mut blob = Vec::with_capacity(104);
    put_string(&mut blob, b"ecdsa-sha2-nistp256");
    put_string(&mut blob, b"nistp256");
    put_string(&mut blob, point);
    PublicKey::from_bytes(&blob).map_err(|e| format!("the TPM key is no key of SSH: {e}"))
}

/// The signature of the TPM as SSH carries it.
pub(super) fn signature_blob(signature: &EcdsaSignature) -> Vec<u8> {
    let mut inner = Vec::with_capacity(72);
    for n in [&signature.r, &signature.s] {
        let zeros = n.iter().take_while(|b| **b == 0).count();
        put_mpint(&mut inner, &n[zeros..]);
    }
    let mut out = Vec::with_capacity(100);
    put_string(&mut out, b"ecdsa-sha2-nistp256");
    put_string(&mut out, &inner);
    out
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// An mpint of SSH (RFC 4251) of a positive number with no leading zeros.
fn put_mpint(out: &mut Vec<u8>, n: &[u8]) {
    let pad = n.first().is_some_and(|b| b & 0x80 != 0);
    out.extend_from_slice(&((n.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(n);
}
