//! The host key's signer (T-856): an RSA host key signs the exchange hash
//! through aws-lc-rs with SHA-512 and SHA-256, and aws-lc-rs's verifier takes
//! each signature; SHA-1, and a key that aws-lc-rs refuses, sign nothing and
//! are never left to russh; Ed25519 and ECDSA keys are russh's. A key of
//! 1024 bits comes from the `rsa` crate, which only a test may use.

use aws_lc_rs::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};
use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};
use russh::keys::EcdsaCurve;
use russh::server::HostKeySigner;

use super::*;
use crate::keygen::{self, KeyKind};

const DATA: &[u8] = b"an exchange hash";

/// The name and the bytes of an SSH signature, each a string.
fn parts(blob: &[u8]) -> (String, Vec<u8>) {
    let word = |b: &[u8]| u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    let name_len = word(blob);
    let name = String::from_utf8(blob[4..4 + name_len].to_vec()).unwrap();
    let rest = &blob[4 + name_len..];
    assert_eq!(rest.len(), 4 + word(rest), "the length of the signature's bytes");
    (name, rest[4..].to_vec())
}

fn components(key: &PrivateKey) -> RsaPublicKeyComponents<Vec<u8>> {
    let KeypairData::Rsa(rsa) = key.key_data() else { panic!("not an RSA key") };
    RsaPublicKeyComponents {
        n: rsa.public().n().as_positive_bytes().unwrap().to_vec(),
        e: rsa.public().e().as_positive_bytes().unwrap().to_vec(),
    }
}

#[test]
fn an_rsa_host_key_signs_through_aws_lc_rs_with_sha2() {
    let key = keygen::generate(KeyKind::Rsa(2048), "host").unwrap();
    let signer = HostSigner::of(&key);
    let public = components(&key);
    for (hash, name, params) in [
        (HashAlg::Sha512, "rsa-sha2-512", &RSA_PKCS1_2048_8192_SHA512),
        (HashAlg::Sha256, "rsa-sha2-256", &RSA_PKCS1_2048_8192_SHA256),
    ] {
        let blob = signer.sign(&key, Some(hash), DATA).expect("not left to russh").expect("signed");
        let (got, signature) = parts(&blob);
        assert_eq!(got, name);
        public.verify(params, DATA, &signature).expect("aws-lc-rs's verifier takes the signature");
    }
}

#[test]
fn sha1_and_a_key_that_aws_lc_rs_refuses_sign_nothing_and_are_not_left_to_russh() {
    let key = keygen::generate(KeyKind::Rsa(2048), "host").unwrap();
    // `ssh-rsa`: SHA-1, which aws-lc-rs does not sign.
    assert!(matches!(HostSigner::of(&key).sign(&key, None, DATA), Some(Err(_))));
    // A key of 1024 bits, which the `rsa` crate would sign.
    let small = PrivateKey::from(RsaKeypair::random(&mut rand::rng(), 1024).unwrap());
    let signer = HostSigner::of(&small);
    for hash in [Some(HashAlg::Sha512), Some(HashAlg::Sha256), None] {
        assert!(matches!(signer.sign(&small, hash, DATA), Some(Err(_))), "{hash:?}");
    }
    // A signer made for an Ed25519 key, asked for an RSA key: refused too.
    let ed25519 = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    assert!(matches!(HostSigner::of(&ed25519).sign(&key, Some(HashAlg::Sha512), DATA), Some(Err(_))));
}

#[test]
fn ed25519_and_ecdsa_keys_are_left_to_russh() {
    for kind in [KeyKind::Ed25519, KeyKind::Ecdsa(EcdsaCurve::NistP256), KeyKind::Ecdsa(EcdsaCurve::NistP521)] {
        let key = keygen::generate(kind, "host").unwrap();
        assert!(HostSigner::of(&key).sign(&key, None, DATA).is_none(), "{:?}", key.algorithm());
    }
}

#[test]
fn the_config_of_serve_carries_the_signer() {
    let key = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    assert!(super::super::config(key).host_key_signer.is_some());
}
