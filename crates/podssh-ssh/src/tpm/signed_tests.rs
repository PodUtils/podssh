//! The signed policies against the TPM in software ([`super::soft`]): a key
//! of a policy key signs; after the boot state changed it does not, and
//! after a signed policy of the new state it signs again; a policy of
//! another key, a changed signature and a ticket of nothing are refused;
//! and each path leaves no handle loaded.

use russh::keys::{EcdsaCurve, PublicKey};

use super::authorize::{self, Authorize, PolicyKey, CC_POLICY_AUTHORIZE};
use super::flow::{self, Transport};
use super::flow_signed;
use super::keyfile::KeyFile;
use super::policy::{self, sha256, ALG_SHA256};
use super::soft::{SoftTpm, RC_VALUE_P4};
use super::wire::{response, Fault};
use super::{check, cmd, Pcrs};
use crate::keygen::{generate, KeyKind};

fn policy_key() -> PolicyKey {
    PolicyKey::new(generate(KeyKind::Ecdsa(EcdsaCurve::NistP256), "policy").unwrap()).unwrap()
}

fn seven() -> Pcrs {
    Pcrs::parse("7").unwrap()
}

/// The messages whose signatures the TPM in software will check: each
/// signed policy's approved digest, then its policyRef.
fn expect(tpm: &mut SoftTpm, file: &KeyFile) {
    for signed in &file.auth_policies {
        let (last, steps) = signed.policy.split_last().unwrap();
        let approved = policy::digest(ALG_SHA256, steps).unwrap();
        let reference = Authorize::parse(&last.1).unwrap().policy_ref;
        tpm.messages.push([approved, reference].concat());
    }
}

/// A TPM whose PCR 7 measured a boot, and a key of `key` made in it.
fn made(key: &PolicyKey) -> (SoftTpm, KeyFile, PublicKey) {
    let mut tpm = SoftTpm::new();
    tpm.extend(7, b"Secure Boot: on, the vendor's keys");
    let (file, area) = flow_signed::make(&mut tpm, seven(), "me@lab", &[1; 32], key, &[9; 32]).unwrap();
    assert_eq!(tpm.loaded(), 0, "make leaves no handle");
    expect(&mut tpm, &file);
    (tpm, file, area.public_key().unwrap())
}

fn sign(tpm: &mut SoftTpm, file: &KeyFile, data: &[u8]) -> Result<Vec<u8>, String> {
    tpm.messages.push(data.to_vec());
    let signed = flow::sign(tpm, file, &sha256(data), [&[2; 32], &[3; 32]]);
    assert_eq!(tpm.loaded(), 0, "sign leaves no handle: {signed:?}");
    signed
}

#[test]
fn after_a_signed_policy_for_the_new_state_the_key_signs_again() {
    let key = policy_key();
    let (mut tpm, file, public) = made(&key);
    assert_eq!(file.policy.len(), 1);
    assert_eq!(file.policy[0].0, CC_POLICY_AUTHORIZE);
    assert_eq!(file.auth_policies.len(), 1);
    check(&public, b"a login", &sign(&mut tpm, &file, b"a login").unwrap()).unwrap();

    tpm.extend(7, b"the firmware's update");
    let why = sign(&mut tpm, &file, b"a login").unwrap_err();
    assert!(why.contains("the PCRs 7 hold other values than each signed policy"), "{why}");
    assert!(!why.contains('\n'), "{why}");

    let new = flow_signed::add_policy(&mut tpm, &file, seven(), &key, Some("firmware 2".into())).unwrap();
    assert_eq!(tpm.loaded(), 0, "add_policy leaves no handle");
    assert_eq!(new.auth_policies.len(), 2);
    assert_eq!(new.auth_policies[0].name.as_deref(), Some("firmware 2"));
    assert_eq!((&new.public, &new.private, &new.policy), (&file.public, &file.private, &file.policy), "the same key");
    expect(&mut tpm, &new);
    check(&public, b"a login", &sign(&mut tpm, &new, b"a login").unwrap()).unwrap();

    // The same state signed again replaces its policy; the file keeps the
    // signed policies as other readers read them.
    let again = flow_signed::add_policy(&mut tpm, &new, seven(), &key, None).unwrap();
    assert_eq!(again.auth_policies.len(), 2);
    assert_eq!(again.auth_policies[1], new.auth_policies[1]);
    assert_eq!(KeyFile::from_pem(&new.to_pem()).unwrap(), new);
    assert_eq!(flow_signed::newest_pcrs(&new), Some(seven()));
}

#[test]
fn a_policy_of_another_key_or_a_changed_signature_is_refused() {
    let key = policy_key();
    let (mut tpm, file, _) = made(&key);
    let other = policy_key();
    let why = flow_signed::add_policy(&mut tpm, &file, seven(), &other, None).unwrap_err();
    assert!(why.contains("not the one that the key file names"), "{why}");

    // A writer of the file signs the state with a key of its own.
    let head = Authorize::parse(&file.policy[0].1).unwrap();
    let steps = file.auth_policies[0].policy[..1].to_vec();
    let mut forged = file.clone();
    forged.auth_policies[0].policy = authorize::signed(steps, &other, &head.policy_ref).unwrap();
    let why = sign(&mut tpm, &forged, b"a login").unwrap_err();
    assert!(why.contains("another policy key"), "{why}");

    // It keeps the policy key's name and puts its own signature: the TPM's
    // check of the signature refuses it.
    let mut swapped = file.clone();
    let mut ours = Authorize::parse(&file.auth_policies[0].policy[1].1).unwrap();
    ours.signature = Authorize::parse(&forged.auth_policies[0].policy[1].1).unwrap().signature;
    swapped.auth_policies[0].policy[1].1 = ours.to_bytes().unwrap();
    let why = sign(&mut tpm, &swapped, b"a login").unwrap_err();
    assert!(why.contains("not the policy key's"), "{why}");

    // It moves the policy to PCR 0, which the signature does not cover.
    let mut moved = file.clone();
    let zero = Pcrs::parse("0").unwrap();
    let values = flow::read_pcrs(&mut tpm, zero).unwrap();
    moved.auth_policies[0].policy[0].1 = policy::pcr_body(zero, &values);
    let why = sign(&mut tpm, &moved, b"a login").unwrap_err();
    assert!(why.contains("not the policy key's"), "{why}");

    let mut none = file.clone();
    none.auth_policies.clear();
    assert!(sign(&mut tpm, &none, b"a login").unwrap_err().contains("holds no signed policy"));
}

/// The planted flow: TPM2_PolicyAuthorize with the ticket of nothing, as a
/// signer that skips the check of the signature would send it, is refused
/// outside a trial.
#[test]
fn a_ticket_of_nothing_is_refused_outside_a_trial() {
    let key = policy_key();
    let (mut tpm, file, _) = made(&key);
    let head = Authorize::parse(&file.policy[0].1).unwrap();
    let (_, steps) = file.auth_policies[0].policy.split_last().unwrap();
    let session = flow::start_session(&mut tpm, cmd::SE_POLICY, &[4; 32]).unwrap();
    flow::run_step(&mut tpm, session, steps[0].0, &steps[0].1).unwrap();
    let approved = policy::digest(ALG_SHA256, steps).unwrap();
    let name = authorize::name(&head.public).unwrap();
    let null = authorize::null_ticket();
    let command = authorize::policy_authorize(session, &approved, &head.policy_ref, &name, &null).unwrap();
    let bytes = tpm.transact(&command).unwrap();
    assert_eq!(response(&bytes, 0).err(), Some(Fault::Tpm(RC_VALUE_P4)));
    flow::flush(&mut tpm, session);
    assert_eq!(tpm.loaded(), 0);
}

/// A policy key that a TPM cannot check, and a key sealed to its PCRs
/// alone, which takes no signed policy: each refused in one line.
#[test]
fn a_policy_key_must_be_p256_and_the_key_must_take_signed_policies() {
    let why = PolicyKey::new(generate(KeyKind::Ed25519, "").unwrap()).err().unwrap();
    assert!(why.contains("ecdsa-sha2-nistp256"), "{why}");
    let mut tpm = SoftTpm::new();
    let (plain, _) = flow::make(&mut tpm, seven(), "", &[1; 32]).unwrap();
    let why = flow_signed::add_policy(&mut tpm, &plain, seven(), &policy_key(), None).unwrap_err();
    assert!(why.contains("sealed to its PCRs alone") && !why.contains('\n'), "{why}");
    assert_eq!(flow_signed::head(&plain), Ok(None));
}
