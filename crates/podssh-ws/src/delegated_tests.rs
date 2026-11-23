//! The delegated credential of a cover name (T-765, T-766): the fields, the
//! window, the exporter binding and the operator key that signs it.

use super::*;
use ed25519_dalek::SigningKey;

/// Two operator keys of the test's: the pinned one, and another that an
/// attacker might hold. Neither is derived from a certificate.
const SEED: [u8; 32] = [0x11; 32];
const OTHER_SEED: [u8; 32] = [0x22; 32];
const NAME: &str = "relay.example.org";

fn key() -> SigningKey {
    issuer_signing_key(&SEED)
}

fn other() -> SigningKey {
    issuer_signing_key(&OTHER_SEED)
}

fn issued(not_before: i64, not_after: i64, exporter: Option<&[u8]>) -> Credential {
    Credential::issue(&key(), NAME, NAME, not_before, not_after, [7; 32], exporter).unwrap()
}

/// T-766: a credential of the pinned key, its name and its exporter verifies;
/// a credential of another issuer, one past its window and one of another
/// key are refused by name.
#[test]
fn a_credential_is_refused_by_name_for_another_issuer_a_window_or_a_key() {
    let exporter = b"the exporter of this connection";
    let pinned = key().verifying_key();
    let credential = issued(1_000, 1_300, Some(exporter));
    assert_eq!(verify(&credential, NAME, &pinned, exporter, 1_100), Ok(()));
    assert_eq!(verify(&credential, NAME, &pinned, exporter, 1_300), Ok(()));

    // Another issuer, though the pinned key signed it: the field is checked
    // before the signature.
    let other_name =
        Credential::issue(&key(), "relay.other.example", "relay.other.example", 1_000, 1_300, [7; 32], Some(exporter))
            .unwrap();
    let refused = verify(&other_name, NAME, &pinned, exporter, 1_100).unwrap_err();
    assert_eq!(refused, pod_cover::CredentialError::WrongIssuer);
    assert!(refused.to_string().contains("another name"), "{refused}");

    // A name that is not the chain's.
    let named = Credential::issue(&key(), NAME, "www.example.org", 1_000, 1_300, [7; 32], Some(exporter)).unwrap();
    assert_eq!(verify(&named, NAME, &pinned, exporter, 1_100), Err(pod_cover::CredentialError::NameMismatch));

    // Past its window, and before it opens.
    let expired = issued(1_000, 1_100, Some(exporter));
    let refused = verify(&expired, NAME, &pinned, exporter, 1_101).unwrap_err();
    assert_eq!(refused, pod_cover::CredentialError::Expired);
    assert!(refused.to_string().contains("expired"), "{refused}");
    assert_eq!(verify(&expired, NAME, &pinned, exporter, 999), Err(pod_cover::CredentialError::NotYetValid));

    // Another exporter of the same name, and a credential of another key: a
    // key that anyone with the certificate could derive would pass this
    // check, so a no-op verifier fails here.
    assert_eq!(
        verify(&credential, NAME, &pinned, b"another connection", 1_100),
        Err(pod_cover::CredentialError::WrongBinding)
    );
    let forged = Credential::issue(&other(), NAME, NAME, 1_000, 1_300, [7; 32], Some(exporter)).unwrap();
    let refused = verify(&forged, NAME, &pinned, exporter, 1_100).unwrap_err();
    assert_eq!(refused, pod_cover::CredentialError::Signature);
    assert!(refused.to_string().contains("signature"), "{refused}");
}

/// Two operator keys are two keys: the pinned one is no other key's, and no
/// certificate byte is part of either.
#[test]
fn the_issuer_key_is_the_operator_s_and_no_other() {
    assert_eq!(key().verifying_key(), issuer_verifying_key(&key()));
    assert_ne!(issuer_verifying_key(&key()), issuer_verifying_key(&other()));
    assert_ne!(issuer_verifying_key(&key()), issuer_verifying_key(&issuer_signing_key(&[0x33; 32])));
}

/// T-765: the credential of the wire is the one that was issued, with the
/// issuer key that the answer names.
#[test]
fn a_credential_survives_its_json() {
    let credential = issued(1_000, 1_300, Some(b"an exporter"));
    let text = encode(&credential);
    assert_eq!(decode(&text).unwrap(), credential);
    let bare = issued(1_000, 1_300, None);
    assert_eq!(decode(&encode(&bare)).unwrap(), bare);
    let with_key = encode_with_issuer(&credential, &key().verifying_key());
    let (decoded, pinned) = decode_with_issuer(&with_key).unwrap();
    assert_eq!(decoded, credential);
    assert_eq!(pinned, key().verifying_key());
    let text = encode(&credential);
    let bad_number = text.replace("\"not_before\":1000", "\"not_before\":\"soon\"");
    let bad_signature = text.replace(&hex::encode(credential.signature), "00");
    for wrong in ["{}", "{\"issuer\":\"x\"}", bad_number.as_str(), bad_signature.as_str()] {
        assert!(decode(wrong).is_err(), "{wrong}");
    }
    let no_key = encode(&credential);
    assert!(decode_with_issuer(&no_key).unwrap_err().contains("issuer_key"));
    let short_key = with_key.replace(&hex::encode(key().verifying_key().as_bytes()), "00");
    assert!(decode_with_issuer(&short_key).is_err(), "a key that is not 32 bytes");
}
