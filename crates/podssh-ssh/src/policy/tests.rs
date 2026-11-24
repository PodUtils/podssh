//! The verdict, as one table: a policy, a change to an observation, and
//! the exit and the fields of each mismatch that must come of it. The
//! observations are the default server lists of OpenSSH and Dropbear as
//! their sources name them; the bytes that a live sshd sends are the CLI
//! test's (`tests/policy_check.rs`).

use super::kexinit::{agreed, key_type_of, lists};
use super::*;

fn names(list: &str) -> Vec<String> {
    list.split(',').map(str::to_string).collect()
}

const OPENSSH_KEX: &str =
    "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,\
ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,ext-info-s,\
kex-strict-s-v00@openssh.com";
const OPENSSH_CIPHERS: &str =
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";
const OPENSSH_MACS: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,\
hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,\
hmac-sha2-512,hmac-sha1";

/// An OpenSSH 10 server with an RSA key of 3072 bits and an Ed25519 key,
/// whose exchange agreed rsa-sha2-512 and got that RSA key.
fn openssh() -> Observed {
    Observed {
        side: Side::Server,
        banner: Some("SSH-2.0-OpenSSH_10.0".into()),
        header: None,
        kex: names(OPENSSH_KEX),
        host_keys: names("rsa-sha2-512,rsa-sha2-256,ssh-ed25519"),
        ciphers: names(OPENSSH_CIPHERS),
        macs: names(OPENSSH_MACS),
        compressions: names("none,zlib@openssh.com"),
        host_key: Some(HostKeySeen {
            requested: "rsa-sha2-512".into(),
            returned: "ssh-rsa".into(),
            bits: 3072,
            ca: None,
        }),
        dh_modulus: Default::default(),
    }
}

/// A Dropbear 2025 server with an Ed25519 key, agreed and got.
fn dropbear() -> Observed {
    Observed {
        side: Side::Server,
        banner: Some("SSH-2.0-dropbear_2025.88".into()),
        header: None,
        kex: names(
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,\
ecdh-sha2-nistp256,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com",
        ),
        host_keys: names("ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256"),
        ciphers: names("chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr"),
        macs: names("hmac-sha2-256,hmac-sha2-512"),
        compressions: names("none"),
        host_key: Some(HostKeySeen {
            requested: "ssh-ed25519".into(),
            returned: "ssh-ed25519".into(),
            bits: 256,
            ca: None,
        }),
        dh_modulus: Default::default(),
    }
}

/// The policy that each list of [`openssh`] meets exactly, then `more`.
fn exact(more: &str) -> Policy {
    let text = format!(
        "name = \"OpenSSH 10 exact\"\nversion = 1\nbanner = \"SSH-2.0-OpenSSH_10.0\"\ncompressions = none, zlib@openssh.com\n\
         host keys = rsa-sha2-512, rsa-sha2-256, ssh-ed25519\nkey exchanges = {OPENSSH_KEX}\nciphers = {OPENSSH_CIPHERS}\n\
         macs = {OPENSSH_MACS}\n{more}"
    );
    parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// [`exact`]'s key exchanges with no marker: ext-info-s and the strict
/// key exchange are not judged then.
fn no_markers() -> Policy {
    let mut policy = exact("");
    policy.kex.as_mut().unwrap().retain(|k| !k.starts_with("ext-info") && !k.starts_with("kex-strict"));
    policy
}

type Change = fn(&mut Observed);

#[test]
fn the_verdict_of_each_case() {
    let none: Change = |_| {};
    let swap_ciphers: Change = |o| o.ciphers.swap(0, 1);
    let rsa_2048: Change = |o| o.host_key.as_mut().unwrap().bits = 2048;
    let rsa_4096: Change = |o| o.host_key.as_mut().unwrap().bits = 4096;
    // Requested rsa-sha2-512, and an Ed25519 key came.
    let wrong_type: Change = |o| {
        let key = o.host_key.as_mut().unwrap();
        (key.returned, key.bits) = ("ssh-ed25519".into(), 256);
    };
    let cert: Change = |o| {
        let key = o.host_key.as_mut().unwrap();
        (key.requested, key.returned) =
            ("rsa-sha2-512-cert-v01@openssh.com".into(), "ssh-rsa-cert-v01@openssh.com".into());
        key.ca = Some(("ecdsa-sha2-nistp256".into(), 256));
        o.host_keys.insert(0, "rsa-sha2-512-cert-v01@openssh.com".into());
    };
    let more_cipher: Change = |o| o.ciphers.push("3des-cbc".into());
    let other_banner: Change = |o| o.banner = Some("SSH-2.0-OpenSSH_9.9".into());
    let no_banner: Change = |o| o.banner = None;
    let no_mlkem: Change = |o| o.kex.retain(|k| !k.starts_with("mlkem"));
    let mac_and_zip: Change = |o| {
        o.macs.pop();
        o.compressions = names("none");
    };
    let dss: Change = |o| o.host_keys.push("ssh-dss".into());
    let gex_2048: Change = |o| {
        o.dh_modulus.insert("diffie-hellman-group-exchange-sha256".into(), 2048);
    };
    let sizes = r#"host_key_sizes = {"rsa-sha2-512": {"hostkey_size": 3072}}"#;
    let ed_size = r#"host_key_sizes = {"ssh-ed25519": {"hostkey_size": 256}}"#;
    let both = r#"host_key_sizes = {"rsa-sha2-512": {"hostkey_size": 3072}, "ssh-ed25519": {"hostkey_size": 256}}"#;
    let ca = r#"host_key_sizes = {"rsa-sha2-512-cert-v01@openssh.com": {"hostkey_size": 3072, "ca_key_type": "ssh-ed25519", "ca_key_size": 256}}"#;
    let gex = "dh_modulus_sizes = {\"diffie-hellman-group-exchange-sha256\": 3072}";
    let optional_cert = "optional host keys = rsa-sha2-512-cert-v01@openssh.com\n";
    #[rustfmt::skip]
    let cases: &[(&str, Policy, Change, i32, &[&str])] = &[
        ("each list as expected", exact(""), none, 0, &[]),
        ("the same ciphers in another order", exact(""), swap_ciphers, 78, &["ciphers"]),
        ("another order where reordering is allowed", exact("allow_algorithm_subset_and_reordering = true"), swap_ciphers, 0, &[]),
        ("a cipher that the policy does not name, subset allowed", exact("allow_algorithm_subset_and_reordering = true"),
            more_cipher, 78, &["ciphers"]),
        ("another banner", exact(""), other_banner, 78, &["banner"]),
        ("no banner at all", exact(""), no_banner, 78, &["banner"]),
        ("another key exchange", exact(""), no_mlkem, 78, &["key exchanges"]),
        ("another MAC and another compression", exact(""), mac_and_zip, 78, &["compressions", "macs"]),
        ("a host key that is not expected", exact(""), dss, 78, &["host keys"]),
        ("an optional host key", exact(optional_cert), cert, 0, &[]),
        ("the size of the key that came", exact(sizes), none, 0, &[]),
        ("a smaller key", exact(sizes), rsa_2048, 78, &["host key size rsa-sha2-512"]),
        ("a larger key, as ssh-audit asks the size itself", exact(sizes), rsa_4096, 78, &["host key size rsa-sha2-512"]),
        ("a larger key where larger keys are allowed", exact(&format!("{sizes}\nallow_larger_keys = true")), rsa_4096, 0, &[]),
        ("a key of another type than the one requested", exact(both), wrong_type, 78, &["host key type"]),
        ("a type that is not requested is not measured", exact(ed_size), none, 69, &[]),
        ("a type that is not offered is not checked", exact(r#"host_key_sizes = {"ssh-dss": {"hostkey_size": 1024}}"#),
            none, 0, &[]),
        ("a certificate signed by another type of CA", exact(&format!("{optional_cert}{ca}")), cert, 78,
            &["CA key type rsa-sha2-512-cert-v01@openssh.com"]),
        ("a modulus that was not measured", exact(gex), none, 69, &[]),
        ("a modulus under its floor", exact(gex), gex_2048, 78, &["DH modulus size diffie-hellman-group-exchange-sha256"]),
        ("a client policy on a server", exact("client policy = true"), none, 78, &["policy side"]),
        ("a policy that names no marker judges the key exchanges alone", no_markers(), none, 0, &[]),
    ];
    for (what, policy, change, exit, fields) in cases {
        let mut observed = openssh();
        change(&mut observed);
        let verdict = evaluate(policy, &observed);
        let got: Vec<&str> = verdict.mismatches.iter().map(|m| m.field.as_str()).collect();
        assert_eq!((verdict.exit(), got.as_slice()), (*exit, *fields), "{what}: {verdict:#?}");
        assert_eq!(verdict.json()["exit"], *exit, "{what}");
    }
}

/// A mismatch names what was expected and what came, as ssh-audit's four
/// fields; the key of another type is not credited with the size of the
/// type requested.
#[test]
fn a_mismatch_says_what_was_expected_and_what_came() {
    let both = r#"host_key_sizes = {"rsa-sha2-512": {"hostkey_size": 3072}, "ssh-ed25519": {"hostkey_size": 256}}"#;
    let mut observed = openssh();
    let key = observed.host_key.as_mut().unwrap();
    (key.returned, key.bits) = ("ssh-ed25519".into(), 256);
    let verdict = evaluate(&exact(both), &observed);
    assert_eq!(
        verdict.mismatches,
        vec![Mismatch {
            field: "host key type".into(),
            expected: vec!["ssh-rsa".into()],
            optional: Vec::new(),
            actual: vec!["ssh-ed25519".into()],
        }]
    );
    // The Ed25519 size is not taken as measured: the exchange asked for RSA.
    assert_eq!(verdict.unmeasured, vec!["host key size ssh-ed25519".to_string()]);
}

/// One form of a mismatch for each line (doctor's, serve's, T-869): the
/// field once, then what was expected and what came; the detail of a
/// verdict says each field once, and a verdict with no mismatch keeps its
/// summary.
#[test]
fn a_mismatch_has_one_form_and_the_detail_names_each_field_once() {
    let one = |field: &str, expected: &[&str], optional: &[&str], actual: &[&str]| Mismatch {
        field: field.into(),
        expected: expected.iter().map(|s| s.to_string()).collect(),
        optional: optional.iter().map(|s| s.to_string()).collect(),
        actual: actual.iter().map(|s| s.to_string()).collect(),
    };
    let cases = [
        (
            one("ciphers", &["aes128-ctr"], &[], &["aes128-ctr", "3des-cbc"]),
            "ciphers: expected aes128-ctr, got aes128-ctr,3des-cbc",
        ),
        (
            one("macs", &["hmac-sha2-256"], &["umac-128@openssh.com"], &[]),
            "macs: expected hmac-sha2-256 (optional umac-128@openssh.com), got nothing",
        ),
        (
            one("host key size rsa-sha2-512", &["3072"], &[], &["2048"]),
            "host key size rsa-sha2-512: expected 3072, got 2048",
        ),
    ];
    for (mismatch, want) in &cases {
        assert_eq!(mismatch.line(), *want);
    }
    let verdict = Verdict {
        policy: "p".into(),
        version: 1,
        mismatches: cases.iter().map(|(m, _)| m.clone()).collect(),
        unmeasured: Vec::new(),
    };
    let detail = verdict.detail();
    assert!(detail.starts_with("the policy \"p\" found 3 mismatch(es): ciphers: expected"), "{detail}");
    for (mismatch, want) in &cases {
        assert_eq!(detail.matches(mismatch.field.as_str()).count(), 1, "{detail}");
        assert!(detail.contains(want), "{detail}");
    }
    let passed = Verdict { mismatches: Vec::new(), ..verdict };
    assert_eq!(passed.detail(), passed.line());
}

/// The same policy judges Dropbear by its own lists: each that differs is
/// named, and a subset policy passes it.
#[test]
fn dropbear_is_judged_by_the_same_rules() {
    let verdict = evaluate(&exact(""), &dropbear());
    let fields: Vec<&str> = verdict.mismatches.iter().map(|m| m.field.as_str()).collect();
    assert_eq!(fields, ["banner", "compressions", "host keys", "key exchanges", "ciphers", "macs"]);
    let subset = parse(
        b"name = \"subset\"\nversion = 3\nallow_algorithm_subset_and_reordering = true\n\
          allow_hostkey_subset_and_reordering = true\nhost keys = ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-256\n\
          ciphers = aes256-ctr, aes128-ctr, chacha20-poly1305@openssh.com\nmacs = hmac-sha2-512, hmac-sha2-256\n\
          host_key_sizes = {\"ssh-ed25519\": {\"hostkey_size\": 256}}\n",
    )
    .unwrap();
    assert_eq!(evaluate(&subset, &dropbear()).exit(), EXIT_PASS);
}

fn kexinit(ten: [&str; 10]) -> Vec<u8> {
    let mut out = vec![20];
    out.extend_from_slice(&[7u8; 16]);
    for list in ten {
        out.extend_from_slice(&(list.len() as u32).to_be_bytes());
        out.extend_from_slice(list.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// A KEXINIT's lists read back; one cut short, or of another message, is
/// refused; the agreed host key is the client's first that the server has.
#[test]
fn a_kexinit_reads_and_a_broken_one_is_refused() {
    let lists_of = ["k1,k2", "rsa-sha2-512,ssh-ed25519", "c1", "c2", "m1", "m2", "none", "none,zlib", "", ""];
    let read = lists(&kexinit(lists_of)).unwrap();
    assert_eq!((read.kex, read.ciphers_s2c, read.compression_s2c), (names("k1,k2"), names("c2"), names("none,zlib")));
    let whole = kexinit(lists_of);
    for cut in [0, 1, 17, 20, whole.len() - 5, whole.len() - 1] {
        assert!(lists(&whole[..cut]).is_err(), "cut at {cut}");
    }
    let mut other = whole.clone();
    other[0] = 21;
    assert!(lists(&other).is_err());
    assert!(lists(&kexinit(["a\u{7}b", "", "", "", "", "", "", "", "", ""])).is_err(), "a control byte");
    let client = names("ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512");
    assert_eq!(agreed(&client, &read.host_keys).as_deref(), Some("ssh-ed25519"));
    assert_eq!(agreed(&names("x"), &read.host_keys), None);
}

#[test]
fn each_algorithm_asks_for_its_key_type() {
    for (algorithm, key) in [
        ("rsa-sha2-512", "ssh-rsa"),
        ("rsa-sha2-256", "ssh-rsa"),
        ("ssh-rsa", "ssh-rsa"),
        ("ssh-ed25519", "ssh-ed25519"),
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"),
        ("rsa-sha2-256-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"),
        ("ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com"),
    ] {
        assert_eq!(key_type_of(algorithm), key, "{algorithm}");
    }
}

/// The judge keeps the reading, ends a connection at a mismatch or with no
/// reading, lets a pass go on, and ends each as a probe.
#[test]
fn the_judge_ends_what_it_must() {
    let go_on = Judge::new(exact(""), false);
    assert_eq!(go_on.judge(Ok(openssh())), None);
    assert!(!go_on.ended());
    assert_eq!(go_on.report("unused").1, EXIT_PASS);
    let refuse = Judge::new(exact(""), false);
    assert!(refuse.judge(Ok(dropbear())).is_some_and(|why| why.contains("refusing to log in")));
    assert!(refuse.ended());
    assert_eq!(refuse.report("unused").1, EXIT_MISMATCH);
    let probe = Judge::new(exact(""), true);
    assert!(probe.judge(Ok(openssh())).is_some());
    assert!(probe.ended());
    let unread = Judge::new(exact(""), true);
    assert!(unread.judge(Err("cut".into())).is_some());
    let (doc, code) = unread.report("unused");
    assert_eq!(
        (code, doc["verdict"].as_str(), doc["why"].as_str()),
        (EXIT_NO_READING, Some("no reading"), Some("cut"))
    );
    let never = Judge::new(exact(""), true);
    assert_eq!(never.report("no connection").0["why"], "no connection");
}
