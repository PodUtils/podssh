//! The glue of podssh over `pod-tpm`, against the TPM in software of
//! `pod-tpm` (its feature `soft`): the forms of SSH of a key and of a
//! signature, the policy key of an SSH key, and the probe of the device.
//! The sequences themselves are `pod-tpm`'s, with its tests against swtpm
//! and the simulator of the reference. podssh's own choice of the parent,
//! the storage key kept at 0x81000001 where the owner's hierarchy has a
//! password, is tested here.

use std::sync::Mutex;

use pod_core::Failure;
use pod_tpm::soft::SoftTpm;

use super::*;
use crate::keygen::{generate, KeyKind};

/// A TPM whose PCR 7 measured a boot. Each has a seed of its own: a key
/// file of one does not load in another.
fn booted() -> SoftTpm {
    let mut tpm = SoftTpm::new(rand::random());
    tpm.extend(7, b"Secure Boot: on, the vendor's keys");
    tpm
}

/// A TPM in software that each operation of a test opens again, as a
/// device is: the TPM to look at, and the way to it.
pub(super) fn shared(tpm: SoftTpm) -> (Arc<Mutex<SoftTpm>>, Opener) {
    let tpm = Arc::new(Mutex::new(tpm));
    let reach = tpm.clone();
    let open: Opener = Arc::new(move || Ok(Box::new(Shared(reach.clone())) as Box<dyn Transport>));
    (tpm, open)
}

struct Shared(Arc<Mutex<SoftTpm>>);

impl Transport for Shared {
    fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>, Failure> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).submit(command)
    }
}

/// A booted TPM, the way to it, a key sealed to its PCR 7 with `comment`,
/// and the key's public key.
pub(super) fn sealed(comment: &str) -> (Arc<Mutex<SoftTpm>>, Opener, KeyFile, PublicKey) {
    let mut tpm = booted();
    let (file, public) = make_on(&mut tpm, Pcrs::parse("7").unwrap(), comment, None).unwrap();
    let (tpm, open) = shared(tpm);
    (tpm, open, file, public)
}

/// `tpm` as Windows leaves a TPM: the owner's hierarchy has a password that
/// nobody knows, so `TPM2_CreatePrimary` gets `TPM_RC_BAD_AUTH` of the
/// first session (0x9A2); each other command goes to `tpm`. pod-tpm's
/// `SoftTpm` has no such knob.
fn owner_password(tpm: &mut SoftTpm) -> impl FnMut(&[u8]) -> Result<Vec<u8>, Failure> + '_ {
    move |command: &[u8]| {
        if command.get(6..10) == Some(&pod_tpm::cmd::CC_CREATE_PRIMARY.to_be_bytes()[..]) {
            return Ok(vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0xA2]);
        }
        tpm.submit(command)
    }
}

/// Where the owner's hierarchy has a password, a key is made under the
/// storage key that the TPM keeps, and its file names that parent; with no
/// such key, one line names both reasons. The key still signs only while
/// its PCRs hold their values. A parent that is neither is refused before
/// anything is sent.
#[test]
fn an_owner_with_a_password_makes_the_key_under_the_kept_storage_key() {
    let mut tpm = booted();
    let seven = Pcrs::parse("7").unwrap();
    let why = make_on(&mut owner_password(&mut tpm), seven.clone(), "", None).unwrap_err();
    assert!(why.contains("has a password") && why.contains("0x81000001"), "{why}");
    assert!(!why.contains('\n'), "{why}");
    assert_eq!(tpm.loaded(), 0, "no handle left");

    tpm.persist(PERSISTENT_SRK);
    let (file, public) = make_on(&mut owner_password(&mut tpm), seven.clone(), "me@lab", None).unwrap();
    assert_eq!(file.parent, PERSISTENT_SRK);
    let again = KeyFile::from_pem(&file.to_pem().unwrap()).unwrap();
    assert_eq!(again.parent, PERSISTENT_SRK, "the parent is written and read");
    check(&public, b"a login", &sign_with(&mut owner_password(&mut tpm), &again, b"a login").unwrap()).unwrap();
    // A key of a policy key takes the same parent.
    let (signed, _) = make_on(&mut owner_password(&mut tpm), seven, "", Some(&policy_key())).unwrap();
    assert_eq!(signed.parent, PERSISTENT_SRK);
    tpm.extend(7, b"Secure Boot: off");
    let why = sign_with(&mut owner_password(&mut tpm), &again, b"a login").unwrap_err();
    assert!(why.contains("hold other values"), "{why}");
    assert_eq!(tpm.loaded(), 0, "no handle left");

    let mut odd = again.clone();
    odd.parent = 0x4000_000B;
    let sent = tpm.commands().len();
    let why = sign_with(&mut tpm, &odd, b"a login").unwrap_err();
    assert!(why.contains("parent is 0x4000000b"), "{why}");
    assert_eq!(tpm.commands().len(), sent, "nothing is sent");
}

/// A policy key of P-256, made as `podssh keygen -t ecdsa` makes it.
fn policy_key() -> PolicyKey {
    PolicyKey::new(generate(KeyKind::Ecdsa(russh::keys::EcdsaCurve::NistP256), "").unwrap()).unwrap()
}

#[test]
fn a_signature_of_the_tpm_is_sshs() {
    let mut tpm = booted();
    let statement = pcr::policy_pcr_now(&mut tpm, &Pcrs::parse("7").unwrap()).unwrap();
    let (file, area) = flow::create_signing(&mut tpm, &mut Random, RH_OWNER, &Policy::new(vec![statement])).unwrap();
    let public = ssh::public_key(&area.point).unwrap();
    assert_eq!(public, public_key(&file).unwrap());
    let blob = sign_with(&mut tpm, &file, b"a login").unwrap();
    check(&public, b"a login", &blob).unwrap();
    assert!(check(&public, b"another login", &blob).is_err());
    assert_eq!(tpm.loaded(), 0, "sign leaves no handle");
}

#[test]
fn a_policy_key_must_be_p256_and_the_key_must_take_signed_policies() {
    let why = PolicyKey::new(generate(KeyKind::Ed25519, "").unwrap()).err().unwrap();
    assert!(why.contains("ecdsa-sha2-nistp256"), "{why}");
    let mut tpm = booted();
    let statement = pcr::policy_pcr_now(&mut tpm, &Pcrs::parse("7").unwrap()).unwrap();
    let (plain, _) = flow::create_signing(&mut tpm, &mut Random, RH_OWNER, &Policy::new(vec![statement])).unwrap();
    assert!(!takes_signed_policies(&plain));
    assert_eq!(signed_pcrs(&plain), None);
}

/// A key under a policy key: the first signed policy of the boot state of
/// now signs; after a change of PCR 7 it does not; a signed policy of the
/// new state lets it sign again.
#[test]
fn after_a_signed_policy_for_the_new_state_the_key_signs_again() {
    let mut tpm = booted();
    let key = policy_key();
    let policy_ref: [u8; 32] = rand::random();
    let own = Policy::new(vec![Statement::authorize(&key.head(&policy_ref).unwrap()).unwrap()]);
    let seven = Pcrs::parse("7").unwrap();
    let first = key.signed_now(&mut tpm, &seven, &policy_ref, None).unwrap();
    let (file, area) = flow::create_signing(&mut tpm, &mut Random, RH_OWNER, &own).unwrap();
    let file = sign::add_signed_policy(&file, first).unwrap();
    assert!(takes_signed_policies(&file));
    assert_eq!(signed_pcrs(&file), Some(seven.clone()));
    let public = ssh::public_key(&area.point).unwrap();
    check(&public, b"a login", &sign_with(&mut tpm, &file, b"a login").unwrap()).unwrap();
    tpm.extend(7, b"the firmware's update");
    let why = sign_with(&mut tpm, &file, b"a login").unwrap_err();
    assert!(why.contains(sign::NO_SIGNED_POLICY), "{why}");
    let again = key.signed_now(&mut tpm, &seven, &policy_ref, Some("firmware 2".into())).unwrap();
    let new = sign::add_signed_policy(&file, again).unwrap();
    check(&public, b"a login", &sign_with(&mut tpm, &new, b"a login").unwrap()).unwrap();
    assert_eq!(tpm.loaded(), 0);
}

#[cfg(unix)]
#[test]
fn a_host_with_no_tpm_says_so() {
    use super::platform::find_in;
    let dir = std::env::temp_dir().join(format!("podssh-tpm-probe-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let none = find_in(&dir, None).unwrap_err();
    assert!(none.starts_with("no TPM: this host shows no"), "{none}");
    std::fs::write(dir.join("tpm0"), b"").unwrap();
    let bare = find_in(&dir, None).unwrap_err();
    assert!(bare.contains("resource manager") && bare.contains("PODSSH_TPM_DEVICE="), "{bare}");
    let plain = find_in(&dir, Some(&dir.join("tpm0"))).unwrap_err();
    assert!(plain.contains("neither a device nor a socket"), "{plain}");
    std::fs::remove_dir_all(&dir).unwrap();
}
