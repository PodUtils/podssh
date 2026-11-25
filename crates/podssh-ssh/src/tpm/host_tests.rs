//! serve's host key in a TPM in software: the stand-in carries the TPM's
//! public key, serve's signer signs each exchange hash in the TPM and the
//! signature verifies, and after the boot state changed the exchange is
//! refused. The plants: russh's own signing of the stand-in, and a
//! stand-in that no TPM holds, each sign nothing.

use signature::Signer;

use super::super::flow;
use super::super::soft::{shared, SoftTpm};
use super::super::{check, Pcrs};
use super::*;

const HASH: &[u8] = b"an exchange hash";

/// A TPM whose PCR 7 measured a boot, a key sealed to it, and the way to it.
fn made() -> (Arc<std::sync::Mutex<SoftTpm>>, Opener, String, PublicKey) {
    let mut tpm = SoftTpm::new();
    tpm.extend(7, b"Secure Boot: on");
    let (file, area) = flow::make(&mut tpm, Pcrs::parse("7").unwrap(), "host@lab", &[1; 32]).unwrap();
    let (tpm, open) = shared(tpm);
    (tpm, open, file.to_pem(), area.public_key().unwrap())
}

#[test]
fn the_tpm_signs_each_exchange_hash_of_a_host_key_sealed_to_it() {
    let (tpm, open, pem, public) = made();
    assert!(is_key_text(&pem));
    let key = stand_in_with(open, &pem).unwrap();
    assert!(is_stand_in(&key));
    assert_eq!(key.public_key().key_data(), public.key_data(), "the TPM's public key, as clients see it");
    assert_eq!(key.comment().as_str_lossy(), "host@lab");
    crate::server::host_key::check(&key).unwrap();

    let config = crate::server::config(key.clone());
    let signer = config.host_key_signer.expect("serve's signer");
    let blob = signer.sign(&key, None, HASH).expect("the signer takes the key").unwrap();
    check(&public, HASH, &blob).unwrap();
    assert_eq!(tpm.lock().unwrap().loaded(), 0, "no handle left");

    // The boot state changes: the exchange is refused, never signed by
    // anything else.
    tpm.lock().unwrap().extend(7, b"Secure Boot: off");
    assert!(signer.sign(&key, None, HASH).expect("still the TPM's").is_err());
}

/// The plants: the stand-in's scalar of zeros signs nothing through
/// ssh-key, as russh would sign it; and a stand-in that no TPM holds is
/// refused by serve's signer, never left to russh.
#[test]
fn a_stand_in_is_never_signed_by_anything_but_its_tpm() {
    let (_tpm, open, pem, _) = made();
    let key = stand_in_with(open, &pem).unwrap();
    let russh_own: Result<russh::keys::ssh_key::Signature, _> = key.key_data().try_sign(HASH);
    assert!(russh_own.is_err(), "a zero scalar signed");

    let (_, _, _, other) = made();
    let orphan = stand_in_key(&other, String::new()).unwrap();
    assert!(is_stand_in(&orphan) && of(&orphan).is_none());
    let signer = crate::server::config(orphan.clone()).host_key_signer.unwrap();
    assert!(matches!(signer.sign(&orphan, None, HASH), Some(Err(_))));

    // An Ed25519 key is no stand-in, and stays russh's.
    let ed = crate::keygen::generate(crate::keygen::KeyKind::Ed25519, "host").unwrap();
    assert!(!is_stand_in(&ed));
    assert!(crate::server::config(ed.clone()).host_key_signer.unwrap().sign(&ed, None, HASH).is_none());
}

/// A key that does not sign now is never served: no TPM, a changed boot
/// state, a file of another TPM, each in one line.
#[test]
fn a_host_key_that_cannot_sign_now_is_refused_at_the_start() {
    let none: Opener = Arc::new(|| Err("no TPM: this host shows no /dev/tpmrm0".to_string()));
    let (_, _, pem, _) = made();
    assert_eq!(stand_in_with(none, &pem).unwrap_err(), "no TPM: this host shows no /dev/tpmrm0");

    let (tpm, open, pem, _) = made();
    tpm.lock().unwrap().extend(7, b"another boot loader");
    let why = stand_in_with(open, &pem).unwrap_err();
    assert!(why.starts_with("the key of the TPM did not sign") && why.contains("hold other values"), "{why}");
    assert!(!why.contains('\n'), "{why}");

    let (_, other, _, _) = made();
    let why = stand_in_with(other, &pem).unwrap_err();
    assert!(why.contains("this TPM cannot load the key"), "{why}");

    assert!(stand_in_with(made().1, "-----BEGIN TSS2 PRIVATE KEY-----\n").is_err());
}
