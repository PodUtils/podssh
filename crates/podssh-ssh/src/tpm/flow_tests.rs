//! The sequences against the TPM in software ([`super::soft`]): a key is
//! made and signs; after the boot state changed it does not; a copy in
//! another TPM does not load; a signer that ignores the policy is refused;
//! and each path leaves no handle loaded.

use super::flow::{self, Transport};
use super::soft::{SoftTpm, RC_AUTH_UNAVAILABLE};
use super::wire::{response, Fault};
use super::{check, cmd, Pcrs};

use super::policy::sha256;

/// A TPM whose PCR 7 measured a boot, and a key sealed to it.
fn made(pcrs: &str) -> (SoftTpm, super::KeyFile, russh::keys::PublicKey) {
    let mut tpm = SoftTpm::new();
    tpm.extend(7, b"Secure Boot: on, the vendor's keys");
    let (file, area) = flow::make(&mut tpm, Pcrs::parse(pcrs).unwrap(), "me@lab", &[1; 32]).unwrap();
    assert_eq!(tpm.loaded(), 0, "make leaves no handle");
    (tpm, file, area.public_key().unwrap())
}

fn sign(tpm: &mut SoftTpm, file: &super::KeyFile, data: &[u8]) -> Result<Vec<u8>, String> {
    tpm.messages.push(data.to_vec());
    let signed = flow::sign(tpm, file, &sha256(data), [&[2; 32], &[3; 32]]);
    assert_eq!(tpm.loaded(), 0, "sign leaves no handle: {signed:?}");
    signed
}

#[test]
fn a_sealed_key_signs_while_the_boot_state_is_the_recorded_one() {
    let (mut tpm, file, public) = made("7");
    let blob = sign(&mut tpm, &file, b"a login").unwrap();
    check(&public, b"a login", &blob).unwrap();
    assert!(check(&public, b"another login", &blob).is_err());
    // The file says what it is sealed to, as other readers read it.
    assert_eq!(file.policy.len(), 1);
    assert_eq!(file.description.as_deref(), Some("me@lab"));
    let again = super::KeyFile::from_pem(&file.to_pem()).unwrap();
    assert_eq!(again, file);
}

#[test]
fn after_the_boot_state_changed_the_key_is_refused_in_one_line() {
    let (mut tpm, file, _) = made("0,7");
    tpm.extend(7, b"Secure Boot: off");
    let why = sign(&mut tpm, &file, b"a login").unwrap_err();
    assert!(why.contains("the PCRs 0,7 hold other values than when the key was made"), "{why}");
    assert!(!why.contains('\n'));
    // A PCR that the key is not sealed to changes nothing.
    let (mut tpm, file, public) = made("7");
    tpm.extend(11, b"a kernel's update");
    check(&public, b"a login", &sign(&mut tpm, &file, b"a login").unwrap()).unwrap();
}

#[test]
fn a_copy_of_the_key_file_does_not_load_in_another_tpm() {
    let (tpm, file, _) = made("7");
    let mut other = SoftTpm::new();
    other.pcrs = tpm.pcrs;
    let why = sign(&mut other, &file, b"a login").unwrap_err();
    assert!(why.contains("this TPM cannot load the key"), "{why}");
}

/// The planted signers: one that authorizes by the empty password, and
/// one whose policy names other PCRs than the key's. The TPM refuses both.
#[test]
fn a_signer_that_ignores_the_policy_is_refused() {
    let (mut tpm, file, _) = made("7");
    let key = flow::load(&mut tpm, &file).unwrap();
    let bytes = tpm.transact(&cmd::sign_by_password(key, &sha256(b"x")).unwrap()).unwrap();
    assert_eq!(response(&bytes, 0).err(), Some(Fault::Tpm(RC_AUTH_UNAVAILABLE)));
    tpm.transact(&cmd::flush(key).unwrap()).unwrap();

    let mut other = file.clone();
    let values = flow::read_pcrs(&mut tpm, Pcrs::parse("0").unwrap()).unwrap();
    other.policy[0].1 = super::policy::pcr_body(Pcrs::parse("0").unwrap(), &values);
    let why = sign(&mut tpm, &other, b"a login").unwrap_err();
    assert!(why.contains("the key's policy was not met"), "{why}");

    other.policy.clear();
    assert!(sign(&mut tpm, &other, b"a login").unwrap_err().contains("no policy"));
}

/// A TPM whose trial reaches another digest than podssh's: no key is made.
#[test]
fn a_policy_that_the_tpm_reads_otherwise_makes_no_key() {
    struct Other(SoftTpm);
    impl Transport for Other {
        fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
            let mut answer = self.0.transact(command)?;
            if command[6..10] == 0x189u32.to_be_bytes() {
                let last = answer.len() - 1;
                answer[last] ^= 1;
            }
            Ok(answer)
        }
    }
    let mut tpm = Other(SoftTpm::new());
    let why = flow::make(&mut tpm, Pcrs::parse("7").unwrap(), "", &[1; 32]).unwrap_err();
    assert!(why.contains("not podssh's"), "{why}");
    assert!(!tpm.0.sent.iter().any(|c| c[6..10] == 0x153u32.to_be_bytes()), "no TPM2_Create was sent");
    assert_eq!(tpm.0.loaded(), 0);
}

/// More than 8 PCRs take two reads, and their values come in order.
#[test]
fn many_pcrs_are_read_in_two_reads() {
    let mut tpm = SoftTpm::new();
    for n in 0..12 {
        tpm.extend(n, &[n as u8]);
    }
    let all = Pcrs::parse("0,1,2,3,4,5,6,7,8,9,10,11").unwrap();
    let values = flow::read_pcrs(&mut tpm, all).unwrap();
    assert_eq!(values.to_vec(), tpm.pcrs[..12].to_vec());
    assert_eq!(tpm.sent.len(), 2);
}

/// The Sign command carries the policy session, with continueSession
/// clear and no HMAC, and a nonce of 32 bytes.
#[test]
fn the_signature_is_asked_in_the_policy_session() {
    let (mut tpm, file, _) = made("7");
    tpm.sent.clear();
    sign(&mut tpm, &file, b"a login").unwrap();
    let signs: Vec<&Vec<u8>> = tpm.sent.iter().filter(|c| c[6..10] == 0x15Du32.to_be_bytes()).collect();
    assert_eq!(signs.len(), 1);
    let sign = signs[0];
    assert_eq!(&sign[0..2], &[0x80, 0x02], "with sessions");
    // The header, the key's handle, the area's size, then the session.
    let session = &sign[18..22];
    assert_eq!(session[0], 0x03, "a policy session's handle");
    assert_eq!(&sign[22..24], &[0, 32], "a nonce of 32 bytes");
    assert_eq!(&sign[56..59], &[0, 0, 0], "continueSession clear, no HMAC");
}

/// No device: one line that says why, before anything is sent.
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
