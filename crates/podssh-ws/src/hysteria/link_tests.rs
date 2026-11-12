use super::*;

// Built from its parts: a scanner of secrets takes a whole link with a
// credential for one.
fn link(scheme: &str, rest: &str) -> String {
    [scheme, "s3cr3t", "-pw@", rest].concat()
}

#[test]
fn a_link_gives_the_host_the_port_the_name_and_the_check() {
    let s = Server::parse(&link("hysteria2://", "h.example:8443/?sni=real.example#My%20server")).unwrap();
    assert_eq!((s.host.as_str(), s.port, s.sni.as_str()), ("h.example", 8443, "real.example"));
    assert_eq!((s.check.clone(), s.obfs.is_none()), (Check::Roots, true));
    assert_eq!((s.shown().as_str(), s.name.as_deref()), ("hysteria2://h.example:8443", Some("My server")));
    assert_eq!(s.auth.text(), "s3cr3t-pw");
    assert!(!format!("{s:?}").contains("s3cr3t"), "{s:?}");
    let short = Server::parse(&link("HY2://", "[2001:db8::1]")).unwrap();
    assert_eq!((short.host.as_str(), short.port, short.sni.as_str()), ("2001:db8::1", 443, "2001:db8::1"));
    // userpass: USER:PASSWORD is the credential whole, percent-decoded.
    let user = Server::parse("hy2://alice:p%40ss@h.example").unwrap();
    assert_eq!(user.auth.text(), "alice:p@ss");
}

#[test]
fn a_pin_reads_as_hysteria_s_client_reads_it_and_stands_for_the_roots() {
    let hex64 = "DE:AD:be:ef".to_string() + &"00".repeat(28);
    let s = Server::parse(&link("hysteria2://", &format!("h.example?insecure=1&pinSHA256={hex64}"))).unwrap();
    let mut want = [0u8; 32];
    want[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(s.check, Check::Pin(want));
    assert_eq!(hex(&want[..4]), "deadbeef");
    for bad in ["", "abc", &"zz".repeat(32), &"00".repeat(33)] {
        assert!(pin(bad).is_err(), "{bad}");
    }
}

#[test]
fn salamander_takes_its_password_and_a_short_one_is_refused() {
    let s = Server::parse(&link("hy2://", "h.example?obfs=salamander&obfs-password=gawr%2Bgura")).unwrap();
    assert_eq!(s.obfs.as_ref().map(|k| k.bytes()), Some(&b"gawr+gura"[..]));
    assert_eq!(s.shown(), "hysteria2://h.example:443 (Salamander)");
    assert!(!format!("{s:?}").contains("gawr"), "{s:?}");
    let spaced = Server::parse(&link("hy2://", "h.example?obfs=salamander&obfs-password=a+b+c")).unwrap();
    assert_eq!(spaced.obfs.as_ref().map(|k| k.bytes()), Some(&b"a b c"[..]), "a + is a space, as Go reads it");
    let short = Server::parse(&link("hy2://", "h.example?obfs=salamander&obfs-password=abc")).unwrap_err();
    assert!(short.starts_with("obfs-password:") && !short.contains("abc"), "{short}");
}

#[test]
fn each_setting_that_podssh_does_not_follow_is_refused_by_its_name_never_the_credential() {
    let refused = [
        ("h.example?insecure=1", "insecure=1 with no pinSHA256"),
        ("h.example:443,5000-6000", "port hopping"),
        ("h.example:5000-6000", "port hopping"),
        ("h.example?obfs=gecko&obfs-password=abcdef", "obfs=gecko"),
        ("h.example?ech=AEX%2B", "ech is not spoken"),
        ("h.example:0", "port 0"),
    ];
    for (rest, words) in refused {
        let why = Server::parse(&link("hysteria2://", rest)).unwrap_err();
        assert!(why.contains(words) && !why.contains("s3cr3t"), "{rest}: {why}");
    }
    assert!(Server::parse("hysteria2+realm://token@r.example/cabin").unwrap_err().contains("realm"));
    assert!(Server::parse("trojan://secret@t.example").unwrap_err().starts_with("a line is hysteria2://"));
    assert!(Server::parse("hysteria2://h.example").unwrap_err().contains("no AUTH@"));
    assert!(Server::parse("hysteria2://@h.example").unwrap_err().contains("AUTH is empty"));
}
