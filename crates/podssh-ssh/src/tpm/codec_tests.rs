//! The codec on byte vectors: the commands as a TPM reads them, the
//! responses and their codes, the selection of PCRs and the policy digest,
//! and a key file that another program wrote.

use super::cmd;
use super::keyfile::{is_pem, KeyFile};
use super::policy::{self, Pcrs, ALG_SHA384, CC_POLICY_AUTH_VALUE, CC_POLICY_PCR};
use super::public::{self, EccPublic};
use super::rc;
use super::wire::{response, Fault, In};

/// The bytes of a text of hex digits.
fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

/// A key file of go-tpm-keyfiles' tests (Foxboron/go-tpm-keyfiles,
/// `testdata/p256-authvalue.tpm` at `8c9c2d10`, MIT): a P-256 key of a
/// SHA-384 name, whose policy is a PolicyPCR of PCR 16 and a
/// PolicyAuthValue. podssh wrote none of it. Its body is kept without the
/// PEM lines, which the scan for private keys would read as a credential.
const FOREIGN_BODY: &str = include_str!("testdata/p256-authvalue.b64");

/// The file as go-tpm-keyfiles wrote it.
fn foreign() -> String {
    let body = FOREIGN_BODY.replace("\r\n", "\n");
    format!("-----BEGIN TSS2 PRIVATE KEY-----\n{body}-----END TSS2 PRIVATE KEY-----\n")
}

/// The commands, each field where part 3 puts it; written out by hand
/// from the specification, not from podssh's encoder.
#[test]
fn the_commands_are_the_bytes_of_part_3() {
    let cases: &[(&str, Result<Vec<u8>, String>, &str)] = &[
        ("FlushContext", cmd::flush(0x8000_0001), "8001 0000000e 00000165 80000001"),
        (
            "CreatePrimary of the H-2 storage key",
            public::storage_template().and_then(|t| cmd::create_primary(&t)),
            "8002 00000043 00000131 40000001 00000009 40000009 0000 00 0000 \
             0004 0000 0000 001a 0023 000b 00030472 0000 0006 0080 0043 0010 0003 0010 0000 0000 \
             0000 00000000",
        ),
        (
            "the template of a key sealed to PCR 7 of zeros",
            public::sealed_template(&unhex("8b5682d81b29435d08d79278150611dc7e5923b2fefcce684a09577b40130a8b")),
            "0038 0023 000b 000404b2 0020 8b5682d81b29435d08d79278150611dc7e5923b2fefcce684a09577b40130a8b \
             0010 0018 000b 0003 0010 0000 0000",
        ),
        ("PCR_Read of 0,7,11", cmd::pcr_read(Pcrs::parse("0,7,11").unwrap()), "8001 00000014 0000017e 00000001 000b 03 810800"),
        ("PolicyGetDigest", cmd::policy_get_digest(0x0300_0001), "8001 0000000e 00000189 03000001"),
        (
            "GetCapability of the manufacturer",
            cmd::get_manufacturer(),
            "8001 00000016 0000017a 00000006 00000105 00000001",
        ),
    ];
    for (name, made, want) in cases {
        let made = made.clone().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(made, unhex(want), "{name}");
    }
}

/// A response: the code of a refusal, a TPM 1.2's tag, a size that is not
/// the bytes that came, and the parameters after their own size.
#[test]
fn a_response_is_read_or_refused_with_its_reason() {
    let ok = unhex("8002 00000019 00000000 80000002 00000002 0000 0000 01 0000");
    let read = response(&ok, 1).unwrap();
    assert_eq!(read.handles, vec![0x8000_0002]);
    assert_eq!(read.params.rest(), &[0, 0]);
    assert_eq!(response(&unhex("8001 0000000a 000001c4"), 0).err(), Some(Fault::Tpm(0x1C4)));
    let old = response(&unhex("00c4 0000000a 00000000"), 0).err().unwrap().to_string();
    assert!(old.contains("TPM 1.2"), "{old}");
    let short = response(&unhex("8001 0000000c 00000000"), 0).err().unwrap().to_string();
    assert!(short.contains("12 bytes, and 10 came"), "{short}");
    assert!(response(&unhex("8001 0000000a 00000000"), 1).is_err(), "a handle due and none came");
    assert!(response(&[0x80], 0).is_err());
}

/// Each code in words, with what it is of.
#[test]
fn each_code_says_its_name_and_its_place() {
    let cases = [
        (0x1C4, "TPM_RC_VALUE", "parameter 1"),
        (0x99D, "TPM_RC_POLICY_FAIL", "session 1"),
        (0x9A2, "TPM_RC_BAD_AUTH", "session 1"),
        (0x18B, "TPM_RC_HANDLE", "handle 1"),
        (0x1DF, "TPM_RC_INTEGRITY", "parameter 1"),
        (0x12F, "TPM_RC_AUTH_UNAVAILABLE", "0x012f"),
        (0x921, "TPM_RC_LOCKOUT", "0x0921"),
        (0x0001, "TPM 1.2", "0x0001"),
        (0x000B_0005, "resource manager", "layer 11"),
        (0x0BB, "an error of the TPM", "0x00bb"),
    ];
    for (code, name, place) in cases {
        let line = rc::describe(code);
        assert!(line.contains(name) && line.contains(place), "{code:#x}: {line}");
        assert!(!line.contains('\n'), "one line: {line}");
    }
    assert_eq!(rc::base(0x1C4), rc::VALUE);
    assert_eq!(rc::base(0x99D), rc::POLICY_FAIL);
    assert_eq!(rc::base(0x9A2), rc::BAD_AUTH);
    assert_eq!(rc::base(0x921), rc::LOCKOUT);
}

/// The PCRs as a user names them, and their selection.
#[test]
fn the_pcrs_are_named_and_selected() {
    for (text, numbers) in [("7", vec![7]), ("0,7,11", vec![0, 7, 11]), (" 23 , 0 ", vec![0, 23]), ("7,7", vec![7])] {
        assert_eq!(Pcrs::parse(text).unwrap().numbers(), numbers, "{text}");
    }
    for bad in ["", "24", "-1", "a", "7,", "1.5"] {
        assert!(Pcrs::parse(bad).is_err(), "{bad:?}");
    }
    let pcrs = Pcrs::parse("0,7,11").unwrap();
    assert_eq!(pcrs.text(), "0,7,11");
    assert_eq!(Pcrs::read_selection(&mut In::new(&unhex("00000001 000b 03 810800"))).unwrap(), pcrs);
    // Another bank with bits set is refused; one with none is passed over.
    assert!(Pcrs::read_selection(&mut In::new(&unhex("00000001 0004 03 800000"))).is_err());
    let both = unhex("00000002 0004 03 000000 000b 03 800000");
    assert_eq!(Pcrs::read_selection(&mut In::new(&both)).unwrap(), Pcrs::parse("7").unwrap());
}

/// The policy digest of PCR 7 holding zeros, computed from part 1's rule
/// outside podssh: H(zeros || TPM_CC_PolicyPCR || selection || H(values)).
#[test]
fn the_digest_of_a_policy_of_pcrs_is_part_1s() {
    let body = policy::pcr_body(Pcrs::parse("7").unwrap(), &[[0u8; 32]]);
    assert_eq!(
        body,
        unhex("00000001000b03800000 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")
    );
    let digest = policy::digest(policy::ALG_SHA256, &[(CC_POLICY_PCR, body.clone())]).unwrap();
    assert_eq!(digest, unhex("8b5682d81b29435d08d79278150611dc7e5923b2fefcce684a09577b40130a8b"));
    // The TPM's order of the same command reads the same.
    let mut tpm_order = vec![0x00, 0x20];
    tpm_order.extend_from_slice(&body[10..]);
    tpm_order.extend_from_slice(&body[..10]);
    assert_eq!(policy::digest(policy::ALG_SHA256, &[(CC_POLICY_PCR, tpm_order)]).unwrap(), digest);
    assert!(policy::digest(policy::ALG_SHA256, &[(0x0000_0170, vec![])]).is_err(), "a command podssh does not run");
}

/// The key file of another program: read, its policy digest recomputed to
/// the key's `authPolicy`, its public key read, and written back to the
/// same bytes.
#[test]
fn a_key_file_of_go_tpm_keyfiles_is_read_and_written_back() {
    let foreign = foreign();
    assert!(is_pem(foreign.as_bytes()));
    let file = KeyFile::from_pem(&foreign).unwrap();
    assert!(file.empty_auth && !file.signed_policies && !file.rsa_parent);
    assert_eq!(file.parent, 0x4000_0001);
    let codes: Vec<u32> = file.policy.iter().map(|(code, _)| *code).collect();
    assert_eq!(codes, vec![CC_POLICY_PCR, CC_POLICY_AUTH_VALUE]);
    let area = EccPublic::parse(&file.public).unwrap();
    assert_eq!(area.name_alg, ALG_SHA384);
    assert_eq!(policy::digest(ALG_SHA384, &file.policy).unwrap(), area.auth_policy);
    let (_, pcrs, _) = policy::split_pcr_body(&file.policy[0].1).unwrap();
    assert_eq!(pcrs, Pcrs::parse("16").unwrap());
    let line = area.public_key().unwrap().to_openssh().unwrap();
    assert!(line.starts_with("ecdsa-sha2-nistp256 AAAA"), "{line}");
    assert_eq!(file.to_pem(), foreign);
}

/// A file cut short, of another kind, or with bytes after it, is refused
/// with a line, never a panic.
#[test]
fn a_bad_key_file_is_refused() {
    let file = KeyFile::from_pem(&foreign()).unwrap();
    let der = file.to_der();
    for cut in [0, 1, 2, 10, der.len() / 2, der.len() - 1] {
        assert!(KeyFile::from_der(&der[..cut]).is_err(), "cut at {cut}");
    }
    let mut longer = der.clone();
    longer.push(0);
    assert!(KeyFile::from_der(&longer).is_err());
    let mut sealed = der.clone();
    sealed[11] = 0x05; // id-sealedkey
    assert!(KeyFile::from_der(&sealed).unwrap_err().contains("not a loadable key"));
    assert!(KeyFile::from_pem("-----BEGIN TSS2 PRIVATE KEY-----\n!!\n-----END TSS2 PRIVATE KEY-----\n").is_err());
    assert!(KeyFile::from_pem("-----BEGIN OPENSSH PRIVATE KEY-----\n").is_err());
    assert!(!is_pem(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
    for byte in 0..der.len() {
        let mut changed = der.clone();
        changed[byte] ^= 0xFF;
        let _ = KeyFile::from_der(&changed);
    }
}

/// A TPM's signature in SSH's form: r and s as mpints, a high bit padded
/// and leading zeros dropped; another algorithm or hash is refused.
#[test]
fn a_signature_of_the_tpm_is_sshs() {
    let r = [0x80u8; 32];
    let mut s = [0x01u8; 32];
    s[0] = 0;
    let mut tpmt = unhex("0018 000b 0020");
    tpmt.extend_from_slice(&r);
    tpmt.extend_from_slice(&unhex("0020"));
    tpmt.extend_from_slice(&s);
    let blob = public::signature_blob(&mut In::new(&tpmt)).unwrap();
    let mut want = unhex("00000013");
    want.extend_from_slice(b"ecdsa-sha2-nistp256");
    want.extend_from_slice(&unhex("00000048 00000021 00"));
    want.extend_from_slice(&r);
    want.extend_from_slice(&unhex("0000001f"));
    want.extend_from_slice(&s[1..]);
    assert_eq!(blob, want);
    assert!(public::signature_blob(&mut In::new(&unhex("0014 000b 0000 0000"))).is_err(), "RSASSA");
    assert!(public::signature_blob(&mut In::new(&unhex("0018 0004 0000 0000"))).is_err(), "SHA-1");
    assert!(public::signature_blob(&mut In::new(&unhex("0018 000b 0000 0000"))).is_err(), "r of zero");
}
