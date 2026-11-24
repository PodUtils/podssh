//! The PCRs that a key is sealed to, and the policy digest that seals it.
//!
//! A policy is a list of policy commands; the TPM extends a digest with each
//! (part 1, "Policy Authorization"): `new = H(old || code || body)`, from a
//! digest of zeros, with the key's name algorithm. For `TPM2_PolicyPCR` the
//! body is the selection of PCRs, then the digest of their values, which is
//! the layout of a key file's `commandPolicy` that openssl_tpm2_engine
//! writes, so the file's bytes are the bytes that the digest hashes. A key
//! whose `authPolicy` is that digest signs only in a session whose policy
//! reached it: only while the PCRs hold those values.

use sha2::{Digest, Sha256, Sha384};

use super::wire::{In, Out};

pub(super) const ALG_SHA256: u16 = 0x000B;
pub(super) const ALG_SHA384: u16 = 0x000C;
pub(super) const CC_POLICY_PCR: u32 = 0x0000_017F;
pub(super) const CC_POLICY_AUTH_VALUE: u32 = 0x0000_016B;
pub(super) const CC_POLICY_PASSWORD: u32 = 0x0000_018C;

/// The PCRs of a platform: 24 in each bank (PC Client profile).
pub const PCR_COUNT: u8 = 24;

/// A set of PCRs of the SHA-256 bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pcrs(u32);

impl Pcrs {
    /// `0,7,11`: each a number of 0 to 23, at least one.
    pub fn parse(text: &str) -> Result<Pcrs, String> {
        let mut bits = 0u32;
        for word in text.split(',') {
            let word = word.trim();
            let n: u8 = word
                .parse()
                .ok()
                .filter(|n| *n < PCR_COUNT)
                .ok_or_else(|| format!("{word:?} is no PCR: the PCRs are 0 to {}", PCR_COUNT - 1))?;
            bits |= 1 << n;
        }
        if bits == 0 {
            return Err("no PCR is named".into());
        }
        Ok(Pcrs(bits))
    }

    /// The numbers, from the lowest.
    pub fn numbers(&self) -> Vec<u8> {
        (0..PCR_COUNT).filter(|n| self.0 & (1 << n) != 0).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// These PCRs without those of `other`.
    pub(super) fn without(&self, other: Pcrs) -> Pcrs {
        Pcrs(self.0 & !other.0)
    }

    pub(super) fn contains(&self, other: Pcrs) -> bool {
        other.0 & !self.0 == 0
    }

    /// The numbers as a user writes them: `0,7,11`.
    pub fn text(&self) -> String {
        let words: Vec<String> = self.numbers().iter().map(u8::to_string).collect();
        words.join(",")
    }

    /// The selection as the TPM takes it (TPML_PCR_SELECTION): one bank,
    /// SHA-256, and three bytes of bits, PCR 0 the lowest bit of the first.
    pub(super) fn selection(&self) -> Vec<u8> {
        let mut out = Out::default();
        out.u32(1).u16(ALG_SHA256).u8(3).raw(&self.0.to_le_bytes()[..3]);
        out.finish().unwrap_or_default()
    }

    /// The PCRs of the SHA-256 bank of a selection; another bank that the
    /// TPM names with bits set is refused, as podssh reads only this one.
    pub(super) fn read_selection(input: &mut In) -> Result<Pcrs, String> {
        let count = input.u32()?;
        if count > 16 {
            return Err(format!("a selection of {count} banks"));
        }
        let mut bits = 0u32;
        for _ in 0..count {
            let bank = input.u16()?;
            let size = input.u8()? as usize;
            let select = input.take(size)?;
            let mut these = 0u32;
            for (i, byte) in select.iter().enumerate() {
                if i < 4 {
                    these |= u32::from(*byte) << (8 * i);
                } else if *byte != 0 {
                    return Err(format!("PCR {} and up, which no platform has", 8 * i));
                }
            }
            if these & !((1 << PCR_COUNT) - 1) != 0 {
                return Err(format!("PCRs {PCR_COUNT} and up, which no platform has"));
            }
            match bank {
                ALG_SHA256 => bits |= these,
                _ if these == 0 => {}
                other => return Err(format!("the bank of algorithm {other:#06x}, where podssh reads SHA-256's")),
            }
        }
        Ok(Pcrs(bits))
    }
}

/// The digest of PCR values, in the order of their numbers: what
/// `TPM2_PolicyPCR` compares and hashes.
pub(super) fn pcr_digest(values: &[[u8; 32]]) -> [u8; 32] {
    sha256(&values.concat())
}

/// SHA-256 of `data`, as an array.
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// The body of `TPM2_PolicyPCR` in a key file: the selection, then the
/// digest of the values.
pub(super) fn pcr_body(pcrs: Pcrs, values: &[[u8; 32]]) -> Vec<u8> {
    let mut body = pcrs.selection();
    body.extend_from_slice(&pcr_digest(values));
    body
}

/// A body of `TPM2_PolicyPCR` split: the selection's bytes, its PCRs, and
/// the digest. Read in the file's layout, then in the TPM's order (the
/// digest as a TPM2B first), which other writers may use.
pub(super) fn split_pcr_body(body: &[u8]) -> Result<(Vec<u8>, Pcrs, Vec<u8>), String> {
    let mut input = In::new(body);
    if let Ok(pcrs) = Pcrs::read_selection(&mut input) {
        let selection = body[..body.len() - input.rest().len()].to_vec();
        if matches!(input.rest().len(), 32 | 48) {
            return Ok((selection, pcrs, input.rest().to_vec()));
        }
    }
    let mut input = In::new(body);
    let digest = input.sized()?.to_vec();
    let start = body.len() - input.rest().len();
    let pcrs = Pcrs::read_selection(&mut input)?;
    if !input.is_empty() || !matches!(digest.len(), 0 | 32 | 48) {
        return Err("the body of TPM2_PolicyPCR in the key file has a layout that podssh does not know".into());
    }
    Ok((body[start..].to_vec(), pcrs, digest))
}

/// The policy digest that `steps` reach, with the hash `alg`: the digest
/// that a key's `authPolicy` must be. A step that podssh cannot recompute
/// is refused.
pub(super) fn digest(alg: u16, steps: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let size = match alg {
        ALG_SHA256 => 32,
        ALG_SHA384 => 48,
        other => {
            return Err(format!("a policy of hash algorithm {other:#06x}, where podssh knows SHA-256 and SHA-384"))
        }
    };
    let mut current = vec![0u8; size];
    for (code, body) in steps {
        let input: Vec<u8> = match *code {
            CC_POLICY_PCR => {
                let (selection, _, digest) = split_pcr_body(body)?;
                // An empty digest means "the values of the day": no file can
                // say what its policy digest is then.
                if digest.len() != size {
                    return Err(format!(
                        "the key file's TPM2_PolicyPCR keeps a digest of {} bytes, where its hash has {size}",
                        digest.len()
                    ));
                }
                [selection, digest].concat()
            }
            // TPM2_PolicyPassword extends with the code of PolicyAuthValue.
            CC_POLICY_AUTH_VALUE | CC_POLICY_PASSWORD if body.is_empty() => Vec::new(),
            other => return Err(format!("a policy command of code {other:#010x}, which podssh does not run")),
        };
        let code = if *code == CC_POLICY_PASSWORD { CC_POLICY_AUTH_VALUE } else { *code };
        let message = [current.as_slice(), &code.to_be_bytes(), &input].concat();
        current = match alg {
            ALG_SHA384 => Sha384::digest(&message).to_vec(),
            _ => Sha256::digest(&message).to_vec(),
        };
    }
    Ok(current)
}
