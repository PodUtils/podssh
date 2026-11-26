//! The key that signs the boot states that a sealed key takes (T-839, the
//! offline update): an ECDSA P-256 key of SSH, kept off the host. It signs
//! `aHash = H(approvedPolicy || policyRef)` of `TPM2_PolicyAuthorize`
//! (`pod_tpm::policy::approved_policy_hash`); the TPM checks the signature
//! with `TPM2_VerifySignature` and `pod-tpm` runs the policy.

use pod_tpm::flow::pcr;
use pod_tpm::policy::approved_policy_hash;
use pod_tpm::public::{external_p256, NULL_SIGNATURE};
use pod_tpm::{AuthPolicy, Authorize, EcdsaSignature, HashAlg, PcrSelection, Policy, Statement, Transport};
use russh::keys::ssh_key::private::{EcdsaKeypair, KeypairData};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
use russh::keys::PrivateKey;

/// The policy key: an open ECDSA P-256 key of SSH and its public area as
/// the TPM loads it.
pub struct PolicyKey {
    key: PrivateKey,
    /// Its public area (`TPM2B_PUBLIC`, whole).
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
        // The blob of SSH: the name, the curve, then the point (RFC 5656).
        let blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| format!("the policy key cannot be read: {}", podssh_ws::text::said(&e)))?;
        let mut rest = blob.as_slice();
        let mut strings = Vec::with_capacity(3);
        for _ in 0..3 {
            let (n, tail) = rest.split_at_checked(4).ok_or("the policy key cannot be read")?;
            let n = u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize;
            let (string, tail) = tail.split_at_checked(n).ok_or("the policy key cannot be read")?;
            strings.push(string);
            rest = tail;
        }
        let point = strings[2];
        let public = external_p256(point).map_err(|e| podssh_ws::text::said(&e))?;
        Ok(PolicyKey { key, public })
    }

    /// The key's own `TPM2_PolicyAuthorize` of `policy_ref`.
    pub(super) fn head(&self, policy_ref: &[u8]) -> Result<Authorize, String> {
        Ok(Authorize {
            public: self.public.clone(),
            policy_ref: policy_ref.to_vec(),
            signature: NULL_SIGNATURE.to_vec(),
        })
    }

    /// A signed policy of `pcrs` as they are now in the TPM of `t`.
    pub(super) fn signed_now(
        &self,
        t: &mut dyn Transport,
        pcrs: &PcrSelection,
        policy_ref: &[u8],
        name: Option<String>,
    ) -> Result<AuthPolicy, String> {
        let statement = pcr::policy_pcr_now(t, pcrs).map_err(|e| podssh_ws::text::said(&e))?;
        let approved =
            Policy::new(vec![statement.clone()]).digest(HashAlg::Sha256).map_err(|e| podssh_ws::text::said(&e))?;
        let a_hash =
            approved_policy_hash(HashAlg::Sha256, &approved, policy_ref).map_err(|e| podssh_ws::text::said(&e))?;
        let signature = self.sign(&a_hash)?.to_tpmt();
        let authorize = Authorize { public: self.public.clone(), policy_ref: policy_ref.to_vec(), signature };
        let steps = vec![statement, Statement::authorize(&authorize).map_err(|e| podssh_ws::text::said(&e))?];
        Ok(AuthPolicy { name, policy: Policy::new(steps) })
    }

    /// The ECDSA signature of the SHA-256 digest `digest`.
    fn sign(&self, digest: &[u8]) -> Result<EcdsaSignature, String> {
        // p256 signs the digest itself: a generic signer of an SSH key could
        // reach the `rsa` crate's private operation (T-257), and `new` let
        // in an ECDSA P-256 key alone.
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) = self.key.key_data() else {
            return Err("the policy key is not an open ECDSA P-256 key".into());
        };
        let signer = p256::ecdsa::SigningKey::from_slice(private.as_slice())
            .map_err(|e| format!("the policy key cannot sign: {}", podssh_ws::text::said(&e)))?;
        let signature: p256::ecdsa::Signature = signer
            .sign_prehash(digest)
            .map_err(|e| format!("the policy key did not sign: {}", podssh_ws::text::said(&e)))?;
        let bytes = signature.to_bytes();
        let (r, s) = bytes.split_at(32);
        Ok(EcdsaSignature { r: r.try_into().unwrap_or([0; 32]), s: s.try_into().unwrap_or([0; 32]) })
    }
}
