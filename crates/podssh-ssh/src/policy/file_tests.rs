//! The policy file: ssh-audit's own forms load unchanged, and each fault
//! of a file is refused with its line, as one table. A field that podssh
//! does not know is refused, never ignored.

use super::*;

/// A policy in the form of ssh-audit's built-in ones (its new form of the
/// sizes, as JSON).
const NEW_FORM: &str = r#"#
# A hardened server, in ssh-audit's grammar.
#
name = "Hardened OpenSSH Server v10.0 (version 1)"
version = 1
changelog = Initial version.
allow_algorithm_subset_and_reordering = true
allow_larger_keys = true
allow_hostkey_subset_and_reordering = true
host keys = ssh-ed25519, rsa-sha2-512, rsa-sha2-256
optional host keys = sk-ssh-ed25519@openssh.com, ssh-ed25519-cert-v01@openssh.com
key exchanges = sntrup761x25519-sha512, curve25519-sha256, curve25519-sha256@libssh.org, ext-info-s, kex-strict-s-v00@openssh.com
ciphers = chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr
macs = hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, umac-128-etm@openssh.com
host_key_sizes = {"rsa-sha2-256": {"hostkey_size": 4096}, "rsa-sha2-512": {"hostkey_size": 4096}, "ssh-ed25519": {"hostkey_size": 256}, "ssh-ed25519-cert-v01@openssh.com": {"hostkey_size": 256, "ca_key_type": "ssh-ed25519", "ca_key_size": 256}}
dh_modulus_sizes = {"diffie-hellman-group-exchange-sha256": 3072}
"#;

/// The older form: one key for each size, and a client policy.
const OLD_FORM: &str = "name = \"Old client\"\r\nversion = 2\r\nbanner = \"SSH-2.0-OpenSSH_8.0\"\r\n\
compressions = none, zlib@openssh.com\r\nhostkey_size_rsa-sha2-256 = 3072\r\n\
cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\r\nhostkey_size_ssh-rsa-cert-v01@openssh.com = 3072\r\n\
dh_modulus_size_diffie-hellman-group-exchange-sha256 = 2048\r\nclient policy = true\r\n";

#[test]
fn ssh_audit_s_forms_load_unchanged() {
    let new = parse(NEW_FORM.as_bytes()).unwrap();
    assert_eq!((new.name.as_str(), new.version), ("Hardened OpenSSH Server v10.0 (version 1)", 1));
    assert!(
        new.allow_algorithm_subset_and_reordering && new.allow_larger_keys && new.allow_hostkey_subset_and_reordering
    );
    assert_eq!(new.optional_host_keys.len(), 2);
    assert_eq!(new.kex.as_ref().map(Vec::len), Some(5));
    let cert = &new.host_key_sizes["ssh-ed25519-cert-v01@openssh.com"];
    assert_eq!(
        (cert.hostkey_size, cert.ca_key_type.as_deref(), cert.ca_key_size),
        (256, Some("ssh-ed25519"), Some(256))
    );
    assert_eq!(new.dh_modulus_sizes["diffie-hellman-group-exchange-sha256"], 3072);
    assert!(!new.client_policy);

    let old = parse(OLD_FORM.as_bytes()).unwrap();
    assert_eq!(old.banner.as_deref(), Some("SSH-2.0-OpenSSH_8.0"));
    assert_eq!(old.host_key_sizes["rsa-sha2-256"].hostkey_size, 3072);
    let cert = &old.host_key_sizes["ssh-rsa-cert-v01@openssh.com"];
    assert_eq!((cert.hostkey_size, cert.ca_key_size), (3072, Some(4096)), "cakey_size_ came before its hostkey_size_");
    assert_eq!(old.dh_modulus_sizes["diffie-hellman-group-exchange-sha256"], 2048);
    assert!(old.client_policy);
}

#[test]
fn each_fault_of_a_file_is_refused_with_its_line() {
    let head = "name = x\nversion = 1\n";
    #[rustfmt::skip]
    let cases: &[(&str, usize, &str)] = &[
        // The field that podssh does not know: refused, never ignored.
        ("frobnicate = yes\n", 3, "does not know"),
        ("Ciphers = aes128-ctr\n", 3, "does not know"),
        ("host_key_sizes = {\"ssh-ed25519\": {\"hostkey_size\": 256, \"strength\": 9}}\n", 3, "does not know"),
        ("ciphers = aes128-ctr\nciphers = aes256-ctr\n", 4, "given twice"),
        ("no equals sign here\n", 3, "no '='"),
        (" = value\n", 3, "no key"),
        ("ciphers = a,,b\n", 3, "an empty name"),
        ("ciphers = aes128-ctr aes256-ctr\n", 3, "no algorithm name"),
        ("allow_larger_keys = yes\n", 3, "true or false"),
        ("hostkey_size_ssh-ed25519 = big\n", 3, "not a size"),
        ("hostkey_size_ssh-ed25519 = 0\n", 3, "from 1 to"),
        ("hostkey_size_ssh-ed25519 = 256\nhostkey_size_ssh-ed25519 = 512\n", 4, "given twice"),
        ("hostkey_size_ssh-rsa = 2048\nhost_key_sizes = {\"ssh-rsa\": {\"hostkey_size\": 3072}}\n", 4, "two sizes"),
        ("host_key_sizes = [1]\n", 3, "not a JSON object"),
        ("host_key_sizes = {\"ssh-rsa\": {}}\n", 3, "no hostkey_size"),
        ("host_key_sizes = {\"ssh-rsa\": {\"hostkey_size\": -1}}\n", 3, "not a size"),
        ("dh_modulus_sizes = {\"diffie-hellman-group-exchange-sha256\": \"big\"}\n", 3, "not a size"),
        ("dh_modulus_sizes = not json\n", 3, "not JSON"),
    ];
    for (more, line, says) in cases {
        let text = format!("{head}{more}");
        let err = parse(text.as_bytes()).expect_err(more);
        assert_eq!(err.line, *line, "{more}: {err}");
        assert!(err.why.contains(says), "{more}: {err}");
    }
    // Faults of the whole file: line 0.
    #[rustfmt::skip]
    let whole: &[(&[u8], &str)] = &[
        (&b"version = 1\n"[..], "no name"),
        (&b"name = x\n"[..], "no version"),
        (&b"name = x\nversion = one\n"[..], "whole number"),
        (&b"name = x\nversion = 1\ncakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n"[..], "has none"),
        (&b"name = \xff\nversion = 1\n"[..], "not UTF-8"),
    ];
    for (text, says) in whole {
        let err = parse(text).expect_err(says);
        assert!(err.why.contains(says), "{says}: {err}");
    }
    let big = vec![b'#'; MAX_BYTES + 1];
    assert!(parse(&big).unwrap_err().why.contains("over the"));
}
