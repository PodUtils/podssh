//! The commands of TPM 2.0 that podssh sends (part 3), each as the bytes
//! of its command and a reading of its response. No session here encrypts
//! a parameter: none of them is secret (a digest to sign, a public
//! signature, the PCRs' values), and the key's private part never leaves
//! the TPM unwrapped.

use super::policy::{Pcrs, ALG_SHA256, CC_POLICY_PCR};
use super::public::{ALG_ECDSA, ALG_NULL};
use super::wire::{command, In, Out, Session, EMPTY_PASSWORD, RH_NULL, RH_OWNER};

pub(super) const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub(super) const CC_CREATE: u32 = 0x0000_0153;
pub(super) const CC_LOAD: u32 = 0x0000_0157;
pub(super) const CC_SIGN: u32 = 0x0000_015D;
pub(super) const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(super) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub(super) const CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub(super) const CC_PCR_READ: u32 = 0x0000_017E;
pub(super) const CC_PCR_EXTEND: u32 = 0x0000_0182;
pub(super) const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;

/// TPM_SE: a policy session, and a trial one that only computes.
pub(super) const SE_POLICY: u8 = 0x01;
pub(super) const SE_TRIAL: u8 = 0x03;
/// TPM_ST_HASHCHECK: the tag of the ticket that a digest of the TPM's own
/// hashing would carry; a NULL one for a key that is not restricted.
const ST_HASHCHECK: u16 = 0x8024;
/// TPM_CAP_TPM_PROPERTIES, and TPM_PT_MANUFACTURER in it.
const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
const PT_MANUFACTURER: u32 = 0x0000_0105;

/// The creation's fields that podssh leaves empty: no outside data and no
/// PCRs in the creation data.
fn creation_tail(out: &mut Out) {
    out.sized(&[]).u32(0);
}

/// The sensitive part of a new key: no authorization value and no data.
fn empty_sensitive(out: &mut Out) {
    out.u16(4).u16(0).u16(0);
}

/// TPM2_CreatePrimary under the owner's hierarchy, with its empty
/// password, of the TPM2B_PUBLIC `template`.
pub(super) fn create_primary(template: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    empty_sensitive(&mut params);
    params.raw(template);
    creation_tail(&mut params);
    command(CC_CREATE_PRIMARY, &[RH_OWNER], &[EMPTY_PASSWORD], &params.finish()?)
}

/// TPM2_Create of the TPM2B_PUBLIC `template` under `parent`.
pub(super) fn create(parent: u32, template: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    empty_sensitive(&mut params);
    params.raw(template);
    creation_tail(&mut params);
    command(CC_CREATE, &[parent], &[EMPTY_PASSWORD], &params.finish()?)
}

/// What TPM2_Create gives: the private and public parts, each a whole
/// TPM2B as a key file keeps it.
pub(super) fn created(params: &mut In) -> Result<(Vec<u8>, Vec<u8>), String> {
    let private = params.sized_whole()?.to_vec();
    let public = params.sized_whole()?.to_vec();
    Ok((private, public))
}

/// TPM2_Load of a key file's parts under `parent`.
pub(super) fn load(parent: u32, private: &[u8], public: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.raw(private).raw(public);
    command(CC_LOAD, &[parent], &[EMPTY_PASSWORD], &params.finish()?)
}

/// TPM2_StartAuthSession of `kind`, bound to nothing and salted with
/// nothing, its hash SHA-256 and no symmetric algorithm.
pub(super) fn start_session(kind: u8, nonce: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.sized(nonce).sized(&[]).u8(kind).u16(ALG_NULL).u16(ALG_SHA256);
    command(CC_START_AUTH_SESSION, &[RH_NULL, RH_NULL], &[], &params.finish()?)
}

/// TPM2_PolicyPCR in `session`: `digest` of the values that the PCRs must
/// hold (the TPM compares it when it is not empty), and their selection.
pub(super) fn policy_pcr(session: u32, digest: &[u8], selection: &[u8]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.sized(digest).raw(selection);
    command(CC_POLICY_PCR, &[session], &[], &params.finish()?)
}

/// TPM2_PolicyGetDigest: the digest that `session` reached.
pub(super) fn policy_get_digest(session: u32) -> Result<Vec<u8>, String> {
    command(CC_POLICY_GET_DIGEST, &[session], &[], &[])
}

/// TPM2_FlushContext of a handle: a key or a session.
pub(super) fn flush(handle: u32) -> Result<Vec<u8>, String> {
    command(CC_FLUSH_CONTEXT, &[], &[], &handle.to_be_bytes())
}

/// TPM2_PCR_Read of `pcrs`.
pub(super) fn pcr_read(pcrs: Pcrs) -> Result<Vec<u8>, String> {
    command(CC_PCR_READ, &[], &[], &pcrs.selection())
}

/// What TPM2_PCR_Read gives: the counter of updates, the PCRs that it
/// read, and their values in the order of their numbers.
pub(super) fn pcr_values(params: &mut In) -> Result<(u32, Pcrs, Vec<Vec<u8>>), String> {
    let counter = params.u32()?;
    let read = Pcrs::read_selection(params)?;
    let count = params.u32()?;
    if count > 32 {
        return Err(format!("{count} values"));
    }
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(params.sized()?.to_vec());
    }
    Ok((counter, read, values))
}

/// TPM2_PCR_Extend of PCR `index` with a SHA-256 `digest`: a test's change
/// of the boot state, under the PCR's empty password.
pub(super) fn pcr_extend(index: u8, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.u32(1).u16(ALG_SHA256).raw(digest);
    command(CC_PCR_EXTEND, &[u32::from(index)], &[EMPTY_PASSWORD], &params.finish()?)
}

/// TPM2_Sign of a SHA-256 `digest` with the key `key`, authorized by the
/// policy session `session`, which ends with the command. The nonce is
/// fresh; the session has no HMAC, as its policy asks for no value.
pub(super) fn sign(key: u32, session: u32, nonce: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    let auth = Session { handle: session, nonce, attributes: 0, hmac: &[] };
    let mut params = Out::default();
    params.sized(digest).u16(ALG_ECDSA).u16(ALG_SHA256);
    params.u16(ST_HASHCHECK).u32(RH_NULL).sized(&[]);
    command(CC_SIGN, &[key], &[auth], &params.finish()?)
}

/// TPM2_Sign authorized by the empty password: what a signer that ignores
/// the policy would send, which a sealed key refuses.
pub(super) fn sign_by_password(key: u32, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.sized(digest).u16(ALG_ECDSA).u16(ALG_SHA256);
    params.u16(ST_HASHCHECK).u32(RH_NULL).sized(&[]);
    command(CC_SIGN, &[key], &[EMPTY_PASSWORD], &params.finish()?)
}

/// TPM2_GetCapability of the manufacturer: the probe's question, which
/// each TPM 2.0 answers.
pub(super) fn get_manufacturer() -> Result<Vec<u8>, String> {
    let mut params = Out::default();
    params.u32(CAP_TPM_PROPERTIES).u32(PT_MANUFACTURER).u32(1);
    command(CC_GET_CAPABILITY, &[], &[], &params.finish()?)
}

/// The manufacturer in the answer: four letters, as `IFX`, `STM ` or
/// `MSFT`, or its number when they are not letters.
pub(super) fn manufacturer(params: &mut In) -> Result<String, String> {
    params.u8()?;
    if params.u32()? != CAP_TPM_PROPERTIES {
        return Err("an answer of another capability".into());
    }
    if params.u32()? == 0 {
        return Err("no property".into());
    }
    if params.u32()? != PT_MANUFACTURER {
        return Err("another property".into());
    }
    let value = params.u32()?.to_be_bytes();
    let text: String = value.iter().filter(|b| **b != 0).map(|b| char::from(*b)).collect();
    if !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Ok(text.trim().to_string());
    }
    Ok(format!("{:#010x}", u32::from_be_bytes(value)))
}
