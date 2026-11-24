//! The offline update of a sealed key (T-839): `TPM2_PolicyAuthorize`. A key
//! sealed this way takes each policy that one signing key, kept off the
//! host, signed: a new boot state needs a new signature, not a new key.
//!
//! The key's own policy is one `TPM2_PolicyAuthorize` that names the signing
//! key and a policyRef of 32 random bytes, so its `authPolicy` is
//! `H(H(0 || TPM_CC_PolicyAuthorize || name) || policyRef)` (part 3,
//! PolicyAuthorize). A signed policy is a list of policy commands (here one
//! `TPM2_PolicyPCR`), then a `TPM2_PolicyAuthorize` whose signature covers
//! `aHash = H(approvedPolicy || policyRef)`, `approvedPolicy` being the
//! digest of the commands before it. To use one, the TPM checks the
//! signature (`TPM2_LoadExternal` of the signing key's public area,
//! `TPM2_VerifySignature`), and its ticket lets `TPM2_PolicyAuthorize` put
//! the key's digest in the session.
//!
//! The key file keeps each `TPM2_PolicyAuthorize` as the draft of the key
//! files says (4.2.1): TPM2B_PUBLIC keySign, TPM2B_DIGEST policyRef, then a
//! TPMT_SIGNATURE, empty (TPM_ALG_NULL) in the key's own policy.

use russh::keys::ssh_key::private::{EcdsaKeypair, KeypairData};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
use russh::keys::PrivateKey;

use super::policy::{sha256, ALG_SHA256};
use super::public::{ALG_ECC, ALG_ECDSA, ALG_NULL, CURVE_P256, DECRYPT, SIGN, USER_WITH_AUTH};
use super::wire::{command, In, Out, RH_NULL, RH_OWNER};

pub(super) const CC_POLICY_AUTHORIZE: u32 = 0x0000_016A;
pub(super) const CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
pub(super) const CC_VERIFY_SIGNATURE: u32 = 0x0000_0177;
/// TPM_ST_VERIFIED: the tag of the ticket of a checked signature.
pub(super) const ST_VERIFIED: u16 = 0x8022;
/// TPMT_SIGNATURE of TPM_ALG_NULL: the key's own `TPM2_PolicyAuthorize`.
pub(super) const NULL_SIGNATURE: &[u8] = &[0x00, 0x10];
/// TPM_ALG_RSASSA: a signature of an RSA policy key, which podssh passes to
/// the TPM as the file holds it.
const ALG_RSASSA: u16 = 0x0014;

/// The attributes of the signing key's public area: those that
/// openssl_tpm2_engine gives an outside ECC key, so that both name the
/// same key alike.
const SIGNER_ATTRIBUTES: u32 = SIGN | DECRYPT | USER_WITH_AUTH;

/// The public area (TPM2B_PUBLIC, whole) of an ECDSA P-256 key from its
/// uncompressed point: no scheme, no symmetric part, named with SHA-256.
pub(super) fn signer_public(point: &[u8]) -> Result<Vec<u8>, String> {
    if point.len() != 65 || point[0] != 4 {
        return Err("the policy key's point is not an uncompressed point of P-256".into());
    }
    let mut area = Out::default();
    area.u16(ALG_ECC).u16(ALG_SHA256).u32(SIGNER_ATTRIBUTES).sized(&[]);
    area.u16(ALG_NULL).u16(ALG_NULL).u16(CURVE_P256).u16(ALG_NULL);
    area.sized(&point[1..33]).sized(&point[33..]);
    let area = area.finish()?;
    let mut out = Out::default();
    out.sized(&area);
    out.finish()
}

/// The name of a public area (TPM2B_PUBLIC, whole): its name algorithm,
/// then the hash of the area with it. podssh names SHA-256 areas only.
pub(super) fn name(public: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = In::new(public);
    let area = input.sized().map_err(|e| format!("the policy key's public area: {e}"))?;
    if !input.is_empty() || area.len() < 4 {
        return Err("the policy key's public area is malformed".into());
    }
    let alg = u16::from_be_bytes([area[2], area[3]]);
    if alg != ALG_SHA256 {
        return Err(format!("the policy key is named with hash {alg:#06x}, where podssh names with SHA-256"));
    }
    let mut name = ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(&sha256(area));
    Ok(name)
}

/// A `TPM2_PolicyAuthorize` as a key file keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Authorize {
    /// The signing key's TPM2B_PUBLIC, whole.
    pub public: Vec<u8>,
    pub policy_ref: Vec<u8>,
    /// TPMT_SIGNATURE, whole: [`NULL_SIGNATURE`] in the key's own policy.
    pub signature: Vec<u8>,
}

impl Authorize {
    pub fn parse(body: &[u8]) -> Result<Authorize, String> {
        let bad = |why: String| format!("the key file's TPM2_PolicyAuthorize cannot be read: {why}");
        let mut input = In::new(body);
        let public = input.sized_whole().map_err(bad)?.to_vec();
        let policy_ref = input.sized().map_err(bad)?.to_vec();
        let signature = input.rest().to_vec();
        check_signature(&signature).map_err(bad)?;
        Ok(Authorize { public, policy_ref, signature })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Out::default();
        out.raw(&self.public).sized(&self.policy_ref).raw(&self.signature);
        out.finish()
    }
}

/// A TPMT_SIGNATURE that podssh passes on: NULL, ECDSA or RSASSA, with
/// nothing after it.
fn check_signature(signature: &[u8]) -> Result<(), String> {
    let mut input = In::new(signature);
    match input.u16()? {
        ALG_NULL => {}
        ALG_ECDSA => {
            input.u16()?;
            input.sized()?;
            input.sized()?;
        }
        ALG_RSASSA => {
            input.u16()?;
            input.sized()?;
        }
        other => return Err(format!("a signature of algorithm {other:#06x}")),
    }
    if !input.is_empty() {
        return Err("bytes after the signature".into());
    }
    Ok(())
}

/// The policy digest after the `TPM2_PolicyAuthorize` of `body`, with the
/// session's `hash` of `size` bytes: it starts again from zeros, then takes
/// the key's name, then the policyRef (`PolicyContextUpdate`).
pub(super) fn digest_after(size: usize, body: &[u8], hash: impl Fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>, String> {
    let authorize = Authorize::parse(body)?;
    let name = name(&authorize.public)?;
    let first = hash(&[vec![0u8; size], CC_POLICY_AUTHORIZE.to_be_bytes().to_vec(), name].concat());
    Ok(hash(&[first, authorize.policy_ref].concat()))
}

/// TPM2_LoadExternal of a public area alone, in the owner's hierarchy: a key
/// of the NULL hierarchy gets a NULL ticket, which TPM2_PolicyAuthorize
/// refuses.
pub(super) fn load_external(public: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.u16(0).raw(public).u32(RH_OWNER);
    command(CC_LOAD_EXTERNAL, &[], &[], &params.finish()?)
}

/// TPM2_VerifySignature of `digest` by the key `key`; its answer is the
/// ticket.
pub(super) fn verify_signature(key: u32, digest: &[u8], signature: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.sized(digest).raw(signature);
    command(CC_VERIFY_SIGNATURE, &[key], &[], &params.finish()?)
}

/// The ticket of TPM2_VerifySignature's answer (TPMT_TK_VERIFIED), whole.
pub(super) fn ticket(params: &mut In) -> Result<Vec<u8>, String> {
    let start = params.rest();
    let tag = params.u16()?;
    if tag != ST_VERIFIED {
        return Err(format!("a ticket of tag {tag:#06x}"));
    }
    params.u32()?;
    params.sized()?;
    Ok(start[..start.len() - params.rest().len()].to_vec())
}

/// The ticket of nothing, which a trial session takes.
pub(super) fn null_ticket() -> Vec<u8> {
    let mut out = Out::default();
    out.u16(ST_VERIFIED).u32(RH_NULL).sized(&[]);
    out.finish().unwrap_or_default()
}

/// TPM2_PolicyAuthorize in `session`.
pub(super) fn policy_authorize(
    session: u32,
    approved: &[u8],
    policy_ref: &[u8],
    name: &[u8],
    ticket: &[u8],
) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.sized(approved).sized(policy_ref).sized(name).raw(ticket);
    command(CC_POLICY_AUTHORIZE, &[session], &[], &params.finish()?)
}

/// The key that signs the boot states that a sealed key takes: an ECDSA
/// P-256 key of SSH (`podssh keygen -t ecdsa`), kept off the host.
pub struct PolicyKey {
    key: PrivateKey,
    /// Its public area as the TPM loads it (TPM2B_PUBLIC, whole).
    pub(super) public: Vec<u8>,
}

impl PolicyKey {
    /// The policy key of `key`, which must be ECDSA P-256 and open: a TPM
    /// checks ECDSA and RSA signatures, and no Ed25519 one.
    pub fn new(key: PrivateKey) -> Result<PolicyKey, String> {
        if key.algorithm() != (Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }) {
            return Err(format!(
                "the policy key is {}, where podssh signs policies with ecdsa-sha2-nistp256 (podssh keygen -t ecdsa)",
                key.algorithm().as_str()
            ));
        }
        let blob = key.public_key().to_bytes().map_err(|e| format!("the policy key cannot be read: {e}"))?;
        let mut input = In::new(&blob);
        let mut strings = Vec::with_capacity(3);
        for _ in 0..3 {
            let n = input.u32()? as usize;
            strings.push(input.take(n)?);
        }
        let public = signer_public(strings[2])?;
        Ok(PolicyKey { key, public })
    }

    /// TPMT_SIGNATURE of `message`: ECDSA over its SHA-256, which is the
    /// TPM's `aHash` when `message` is `approvedPolicy || policyRef`.
    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        // p256 signs the digest itself: a generic signer of an SSH key could
        // reach the `rsa` crate's private operation (T-257), and `new` let
        // in an ECDSA P-256 key alone.
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) = self.key.key_data() else {
            return Err("the policy key is not an open ECDSA P-256 key".into());
        };
        let signer = p256::ecdsa::SigningKey::from_slice(private.as_slice())
            .map_err(|e| format!("the policy key cannot sign: {e}"))?;
        let digest = sha2::Sha256::digest(message);
        let signature: p256::ecdsa::Signature =
            signer.sign_prehash(&digest).map_err(|e| format!("the policy key did not sign: {e}"))?;
        let (r, s) = signature.split_bytes();
        let mut out = Out::default();
        out.u16(ALG_ECDSA).u16(ALG_SHA256).sized(&r).sized(&s);
        out.finish()
    }
}

/// A signed policy: `steps`, then the `TPM2_PolicyAuthorize` whose
/// signature by `key` covers their digest and `policy_ref`.
pub(super) fn signed(
    mut steps: Vec<(u32, Vec<u8>)>,
    key: &PolicyKey,
    policy_ref: &[u8],
) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let approved = super::policy::digest(ALG_SHA256, &steps)?;
    let signature = key.sign(&[approved.as_slice(), policy_ref].concat())?;
    let body = Authorize { public: key.public.clone(), policy_ref: policy_ref.to_vec(), signature }.to_bytes()?;
    steps.push((CC_POLICY_AUTHORIZE, body));
    Ok(steps)
}
