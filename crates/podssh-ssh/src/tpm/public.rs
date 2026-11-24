//! The public area of a TPM key (TPMT_PUBLIC): the two templates that
//! podssh asks the TPM for, the reading of an ECC key's area, and the key
//! and its signatures in SSH's formats (`ecdsa-sha2-nistp256`, RFC 5656).

use russh::keys::PublicKey;

use super::policy::ALG_SHA256;
use super::wire::{In, Out};

pub(super) const ALG_ECC: u16 = 0x0023;
pub(super) const ALG_NULL: u16 = 0x0010;
pub(super) const ALG_AES: u16 = 0x0006;
pub(super) const ALG_CFB: u16 = 0x0043;
pub(super) const ALG_ECDSA: u16 = 0x0018;
pub(super) const ALG_ECDAA: u16 = 0x001A;
pub(super) const CURVE_P256: u16 = 0x0003;

/// TPMA_OBJECT's bits.
pub(super) const FIXED_TPM: u32 = 1 << 1;
pub(super) const FIXED_PARENT: u32 = 1 << 4;
pub(super) const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub(super) const USER_WITH_AUTH: u32 = 1 << 6;
pub(super) const ADMIN_WITH_POLICY: u32 = 1 << 7;
pub(super) const NO_DA: u32 = 1 << 10;
pub(super) const RESTRICTED: u32 = 1 << 16;
pub(super) const DECRYPT: u32 = 1 << 17;
pub(super) const SIGN: u32 = 1 << 18;

/// The storage key under the owner's hierarchy that the draft of the key
/// files names: the H-2 template of the TCG (EK Credential Profile B.4.5,
/// as Provisioning Guidance 7.5.1 changes it for storage), NIST P-256 with
/// unique fields of length zero. Each reader of the files makes the same
/// key again from it, so the TPM's seed alone decides it.
pub(super) fn storage_template() -> Result<Vec<u8>, String> {
    let attributes = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | NO_DA | RESTRICTED | DECRYPT;
    let mut area = Out::default();
    area.u16(ALG_ECC).u16(ALG_SHA256).u32(attributes).sized(&[]);
    area.u16(ALG_AES).u16(128).u16(ALG_CFB);
    area.u16(ALG_NULL).u16(CURVE_P256).u16(ALG_NULL);
    area.sized(&[]).sized(&[]);
    sized(area)
}

/// The attributes of a sealed key: made in this TPM and bound to it and to
/// its parent; it signs and does nothing else; and with no
/// `userWithAuth`, the TPM takes no password for it, only its policy.
pub(super) const SEALED: u32 = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | ADMIN_WITH_POLICY | NO_DA | SIGN;

/// The template of a sealed key: ECDSA with SHA-256 on P-256, whose
/// authorization is `policy` alone.
pub(super) fn sealed_template(policy: &[u8]) -> Result<Vec<u8>, String> {
    let mut area = Out::default();
    area.u16(ALG_ECC).u16(ALG_SHA256).u32(SEALED).sized(policy);
    area.u16(ALG_NULL).u16(ALG_ECDSA).u16(ALG_SHA256).u16(CURVE_P256).u16(ALG_NULL);
    area.sized(&[]).sized(&[]);
    sized(area)
}

fn sized(area: Out) -> Result<Vec<u8>, String> {
    let area = area.finish()?;
    let mut out = Out::default();
    out.sized(&area);
    out.finish()
}

/// What podssh reads of an ECC key's public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublic {
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub curve: u16,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl EccPublic {
    /// Read a TPM2B_PUBLIC whole, its length included.
    pub fn parse(whole: &[u8]) -> Result<EccPublic, String> {
        let bad = |why: String| format!("the public area of the TPM key: {why}");
        let mut outer = In::new(whole);
        let area = outer.sized().map_err(bad)?;
        if !outer.is_empty() {
            return Err(bad("bytes after it".into()));
        }
        let mut input = In::new(area);
        let kind = input.u16().map_err(bad)?;
        if kind != ALG_ECC {
            return Err(format!("the TPM key is of algorithm {kind:#06x}, where podssh signs with ECC keys"));
        }
        let name_alg = input.u16().map_err(bad)?;
        let attributes = input.u32().map_err(bad)?;
        let auth_policy = input.sized().map_err(bad)?.to_vec();
        // TPMS_ECC_PARMS: symmetric, scheme, curve, kdf; each a selector,
        // with its details unless it is NULL.
        if input.u16().map_err(bad)? != ALG_NULL {
            input.take(4).map_err(bad)?;
        }
        match input.u16().map_err(bad)? {
            ALG_NULL => {}
            ALG_ECDAA => {
                input.take(4).map_err(bad)?;
            }
            _ => {
                input.u16().map_err(bad)?;
            }
        }
        let curve = input.u16().map_err(bad)?;
        if input.u16().map_err(bad)? != ALG_NULL {
            input.u16().map_err(bad)?;
        }
        let x = input.sized().map_err(bad)?.to_vec();
        let y = input.sized().map_err(bad)?.to_vec();
        if !input.is_empty() {
            return Err(bad("bytes after the point".into()));
        }
        Ok(EccPublic { name_alg, attributes, auth_policy, curve, x, y })
    }

    /// The point as SEC 1 writes it, uncompressed: 0x04, X, Y.
    pub fn point(&self) -> Result<Vec<u8>, String> {
        if self.curve != CURVE_P256 {
            return Err(format!("the TPM key is on curve {:#06x}, where podssh signs on NIST P-256", self.curve));
        }
        let mut point = vec![4u8];
        for c in [&self.x, &self.y] {
            let c = strip(c);
            if c.len() > 32 {
                return Err("the TPM key's point has a coordinate of more than 32 bytes".into());
            }
            point.extend(std::iter::repeat_n(0, 32 - c.len()));
            point.extend_from_slice(c);
        }
        Ok(point)
    }

    /// The key as SSH carries it.
    pub fn public_key(&self) -> Result<PublicKey, String> {
        let mut blob = Vec::with_capacity(104);
        put_string(&mut blob, b"ecdsa-sha2-nistp256");
        put_string(&mut blob, b"nistp256");
        put_string(&mut blob, &self.point()?);
        PublicKey::from_bytes(&blob).map_err(|e| format!("the TPM key is no key of SSH: {e}"))
    }
}

/// The signature that `TPM2_Sign` gave (TPMT_SIGNATURE) as SSH carries
/// it: the name, then r and s as mpints.
pub(super) fn signature_blob(input: &mut In) -> Result<Vec<u8>, String> {
    let alg = input.u16()?;
    if alg != ALG_ECDSA {
        return Err(format!("the TPM signed with algorithm {alg:#06x}, not ECDSA"));
    }
    let hash = input.u16()?;
    if hash != ALG_SHA256 {
        return Err(format!("the TPM signed with hash {hash:#06x}, not SHA-256"));
    }
    let r = input.sized()?;
    let s = input.sized()?;
    let mut inner = Vec::with_capacity(72);
    for n in [r, s] {
        let n = strip(n);
        if n.is_empty() || n.len() > 32 {
            return Err("the TPM's signature has an r or an s out of range".into());
        }
        put_mpint(&mut inner, n);
    }
    let mut out = Vec::with_capacity(100);
    put_string(&mut out, b"ecdsa-sha2-nistp256");
    put_string(&mut out, &inner);
    Ok(out)
}

/// `n` without its leading zeros.
fn strip(n: &[u8]) -> &[u8] {
    let zeros = n.iter().take_while(|b| **b == 0).count();
    &n[zeros..]
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
