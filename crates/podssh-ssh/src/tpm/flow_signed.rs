//! The sequences of a key that takes signed policies (T-839, the offline
//! update; [`super::authorize`] has the layout): its making, a signature
//! with it, and a new signed policy for the boot state of now. Each flushes
//! each handle that it made on each path, as [`super::flow`] does.

use super::authorize::{self, Authorize, PolicyKey, CC_POLICY_AUTHORIZE, NULL_SIGNATURE};
use super::cmd;
use super::flow::{self, flush, run, Transport, Unmet};
use super::keyfile::{AuthPolicy, KeyFile};
use super::policy::{self, Pcrs, ALG_SHA256, CC_POLICY_PCR};
use super::public::EccPublic;
use super::rc;
use super::wire::{Fault, In};

/// A new key whose policy is "a policy that `key` signed", with the
/// policyRef `policy_ref`, and its first signed policy: `pcrs` as they are
/// now. The TPM's trial of the policy must reach podssh's digest.
pub(super) fn make<T: Transport + ?Sized>(
    t: &mut T,
    pcrs: Pcrs,
    description: &str,
    nonce: &[u8; 32],
    key: &PolicyKey,
    policy_ref: &[u8; 32],
) -> Result<(KeyFile, EccPublic), String> {
    let head =
        Authorize { public: key.public.clone(), policy_ref: policy_ref.to_vec(), signature: NULL_SIGNATURE.to_vec() };
    let steps = vec![(CC_POLICY_AUTHORIZE, head.to_bytes()?)];
    let wanted = policy::digest(ALG_SHA256, &steps)?;
    let name = authorize::name(&key.public)?;
    // A trial session checks no ticket: the ticket of nothing will do.
    let trial = flow::trial_digest(t, nonce, |session| {
        authorize::policy_authorize(session, &[], policy_ref, &name, &authorize::null_ticket())
    })?;
    if trial != wanted {
        return Err("the TPM's digest of the policy is not podssh's: no key is made".into());
    }
    // The first policy is signed before the key exists: a signer that
    // fails leaves nothing in the TPM to flush.
    let first = signed_now(t, pcrs, key, policy_ref, None)?;
    let (private, public_area, area) = flow::create_sealed(t, &wanted)?;
    let mut file = flow::sealed_file(steps, description, public_area, private);
    file.auth_policies.push(first);
    Ok((file, area))
}

/// A signed policy of `pcrs` as they are now in this TPM.
fn signed_now<T: Transport + ?Sized>(
    t: &mut T,
    pcrs: Pcrs,
    key: &PolicyKey,
    policy_ref: &[u8],
    name: Option<String>,
) -> Result<AuthPolicy, String> {
    let values = flow::read_pcrs(t, pcrs)?;
    let steps = vec![(CC_POLICY_PCR, policy::pcr_body(pcrs, &values))];
    Ok(AuthPolicy { name, policy: authorize::signed(steps, key, policy_ref)? })
}

/// `file` with a new signed policy before the others: `pcrs` as they are
/// now, signed by `key`, which must be the policy key that the file names.
/// A policy of the same PCRs and values replaces the older one.
pub(super) fn add_policy<T: Transport + ?Sized>(
    t: &mut T,
    file: &KeyFile,
    pcrs: Pcrs,
    key: &PolicyKey,
    name: Option<String>,
) -> Result<KeyFile, String> {
    let own = head(file)?.ok_or(
        "the key is sealed to its PCRs alone, with no policy key: a new boot state needs a new key \
         (podssh keygen -t ecdsa-tpm -O policy-key=FILE makes one that takes signed policies)",
    )?;
    if own.public != key.public {
        return Err("the policy key is not the one that the key file names".into());
    }
    let signed = signed_now(t, pcrs, key, &own.policy_ref, name)?;
    let mut new = file.clone();
    let unsigned = |p: &AuthPolicy| p.policy.split_last().map(|(_, steps)| steps.to_vec());
    new.auth_policies.retain(|p| unsigned(p) != unsigned(&signed));
    new.auth_policies.insert(0, signed);
    Ok(new)
}

/// The key's own `TPM2_PolicyAuthorize`, when its policy begins with one.
pub(super) fn head(file: &KeyFile) -> Result<Option<Authorize>, String> {
    match file.policy.first() {
        Some((code, body)) if *code == CC_POLICY_AUTHORIZE => Authorize::parse(body).map(Some),
        _ => Ok(None),
    }
}

/// The PCRs of the newest signed policy of `file`, if it names some.
pub(super) fn newest_pcrs(file: &KeyFile) -> Option<Pcrs> {
    let newest = file.auth_policies.first()?;
    let (_, body) = newest.policy.iter().find(|(code, _)| *code == CC_POLICY_PCR)?;
    policy::split_pcr_body(body).ok().map(|(_, pcrs, _)| pcrs)
}

/// The signature of `digest` with a key that takes signed policies: each
/// signed policy of the file in turn, the newest first, until one is met
/// (the draft of the key files, 5.2).
pub(super) fn sign<T: Transport + ?Sized>(
    t: &mut T,
    file: &KeyFile,
    head: &Authorize,
    digest: &[u8; 32],
    nonces: [&[u8; 32]; 2],
) -> Result<Vec<u8>, String> {
    if file.auth_policies.is_empty() {
        return Err("the key file holds no signed policy: sign one for this boot state with \
                    podssh keygen -t ecdsa-tpm -O add-policy and its policy key"
            .into());
    }
    let key = flow::load(t, file)?;
    let mut unmet = Vec::with_capacity(file.auth_policies.len());
    for signed in &file.auth_policies {
        match attempt(t, key, head, signed, &file.policy[1..], digest, nonces) {
            Ok(blob) => {
                flush(t, key);
                return Ok(blob);
            }
            Err(why) => unmet.push(why),
        }
    }
    flush(t, key);
    Err(summary(unmet))
}

/// One signed policy, in a fresh session, then the rest of the key's own
/// policy, then the signature.
fn attempt<T: Transport + ?Sized>(
    t: &mut T,
    key: u32,
    head: &Authorize,
    signed: &AuthPolicy,
    rest: &[(u32, Vec<u8>)],
    digest: &[u8; 32],
    nonces: [&[u8; 32]; 2],
) -> Result<Vec<u8>, Unmet> {
    let other = |why: &str| Unmet::Other(why.to_string());
    let (last, steps) = signed.policy.split_last().ok_or_else(|| other("a signed policy with no command"))?;
    if last.0 != CC_POLICY_AUTHORIZE || steps.iter().any(|(code, _)| *code == CC_POLICY_AUTHORIZE) {
        return Err(other("a signed policy that is not commands, then one TPM2_PolicyAuthorize"));
    }
    let authorizing = Authorize::parse(&last.1).map_err(Unmet::Other)?;
    if authorizing.public != head.public || authorizing.policy_ref != head.policy_ref {
        return Err(other("a signed policy of another policy key, or for another key"));
    }
    if rest.iter().any(|(code, _)| *code == CC_POLICY_AUTHORIZE) {
        return Err(other("a key whose policy has a second TPM2_PolicyAuthorize"));
    }
    let approved = policy::digest(ALG_SHA256, steps).map_err(Unmet::Other)?;
    let session = flow::start_session(t, cmd::SE_POLICY, nonces[0]).map_err(Unmet::Other)?;
    let signature = (|| -> Result<Vec<u8>, Unmet> {
        for (code, body) in steps {
            flow::run_step(t, session, *code, body)?;
        }
        take_signed(t, session, &authorizing, &approved).map_err(Unmet::Other)?;
        for (code, body) in rest {
            flow::run_step(t, session, *code, body)?;
        }
        flow::sign_in(t, key, session, nonces[1], digest).map_err(Unmet::Other)
    })();
    // A signature that succeeded ended the session (continueSession clear).
    if signature.is_err() {
        flush(t, session);
    }
    signature
}

/// The TPM checks the signature of `signed` over the approved policy, and
/// its ticket lets TPM2_PolicyAuthorize put the key's digest in `session`.
fn take_signed<T: Transport + ?Sized>(
    t: &mut T,
    session: u32,
    signed: &Authorize,
    approved: &[u8],
) -> Result<(), String> {
    let name = authorize::name(&signed.public)?;
    let a_hash = policy::sha256(&[approved, signed.policy_ref.as_slice()].concat());
    let command = authorize::load_external(&signed.public)?;
    let (handles, params) = run(t, &command, 1).map_err(|e| format!("the TPM did not load the policy key: {e}"))?;
    let external = *handles.first().ok_or("the TPM gave no handle of the policy key")?;
    let checked = (|| -> Result<Vec<u8>, String> {
        if In::new(&params).sized()? != name.as_slice() {
            return Err("the TPM names the policy key otherwise than podssh does".into());
        }
        let command = authorize::verify_signature(external, &a_hash, &signed.signature)?;
        let (_, params) = run(t, &command, 0).map_err(|e| match e {
            Fault::Tpm(code) if rc::base(code) == rc::SIGNATURE => {
                "the signature of the policy is not the policy key's: the key file was changed".to_string()
            }
            other => format!("the TPM did not check the policy's signature: {other}"),
        })?;
        authorize::ticket(&mut In::new(&params)).map_err(|e| format!("the TPM's ticket cannot be read: {e}"))
    })();
    flush(t, external);
    let ticket = checked?;
    let command = authorize::policy_authorize(session, approved, &signed.policy_ref, &name, &ticket)?;
    run(t, &command, 0).map(drop).map_err(|e| flow::refused(e, "the TPM did not take the signed policy"))
}

/// One line for the signed policies of which none was met.
fn summary(unmet: Vec<Unmet>) -> String {
    let changed: Vec<Pcrs> =
        unmet.iter().filter_map(|u| if let Unmet::Changed(pcrs) = u { Some(*pcrs) } else { None }).collect();
    if !changed.is_empty() && changed.len() == unmet.len() {
        return format!(
            "the PCRs {} hold other values than each signed policy of the key names: the boot state changed; \
             once you know why, sign a policy for it with podssh keygen -t ecdsa-tpm -O add-policy",
            changed[0].text()
        );
    }
    let lines: Vec<String> = unmet.into_iter().map(Unmet::line).collect();
    format!("no signed policy of the key is met: {}", lines.join("; "))
}
