use super::*;

// Built from its parts: a scanner of secrets takes a whole link with a
// password for a credential.
fn link(rest: &str) -> String {
    ["tuic://", "123e4567-e89b-12d3-a456-426614174000", ":", "s3cr3t", "-pw@", rest].concat()
}

#[test]
fn a_link_gives_the_uuid_s_bytes_the_password_the_name_and_the_alpn() {
    let server =
        Server::parse(&link("t.example:8443?sni=front.example&alpn=h3,spdy%2F3&congestion_control=bbr#mine")).unwrap();
    let want = [0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00];
    assert_eq!(server.uuid.0, want);
    assert_eq!(server.password.bytes(), b"s3cr3t-pw");
    assert_eq!((server.host.as_str(), server.port, server.sni.as_str()), ("t.example", 8443, "front.example"));
    assert_eq!(server.alpn, ["h3", "spdy/3"]);
    assert_eq!(server.name.as_deref(), Some("mine"));
    assert_eq!(server.shown(), "tuic://t.example:8443");
    let shown = format!("{server:?}");
    assert!(!shown.contains("s3cr3t") && !shown.contains("123e4567"), "{shown}");
}

#[test]
fn with_no_sni_and_no_alpn_tls_checks_the_host_and_offers_h3() {
    let server = Server::parse(&link("[2001:db8::1]:443?udp_relay_mode=native")).unwrap();
    assert_eq!((server.host.as_str(), server.sni.as_str()), ("2001:db8::1", "2001:db8::1"));
    assert_eq!(server.alpn, ["h3"]);
    assert_eq!(server.shown(), "tuic://[2001:db8::1]:443");
    let peer = Server::parse(&link("t.example:443?peer=p.example")).unwrap();
    assert_eq!(peer.sni, "p.example");
}

#[test]
fn a_uuid_without_hyphens_and_a_password_with_colons_are_read() {
    let line = ["tuic://", "123E4567E89B12D3A456426614174000", ":", "a:b%3Ac", "@t.example:1"].concat();
    let server = Server::parse(&line).unwrap();
    assert_eq!(server.uuid.0[0], 0x12);
    assert_eq!(server.password.bytes(), b"a:b:c");
}

#[test]
fn each_refusal_names_the_setting_and_never_the_credential() {
    for (rest, starts) in [
        ("t.example:443?allow_insecure=1", "allow_insecure is refused"),
        ("t.example:443?insecure=true", "allow_insecure is refused"),
        ("t.example:443?version=4", "version=4 is not spoken"),
        ("t.example:443?congestion_control=brutal", "congestion_control=brutal is no controller"),
        ("t.example", "the link names no port"),
        ("t.example:0", "port 0 is no port"),
    ] {
        let why = Server::parse(&link(rest)).unwrap_err();
        assert!(why.starts_with(starts), "{rest}: {why}");
        assert!(!why.contains("s3cr3t") && !why.contains("123e4567"), "{why}");
    }
    let no_uuid = Server::parse("tuic://not-a-uuid:pw@t.example:443").unwrap_err();
    assert_eq!(no_uuid, "the user is not a UUID");
    let no_password = Server::parse("tuic://123e4567-e89b-12d3-a456-426614174000@t.example:443").unwrap_err();
    assert!(no_password.contains("no :PASSWORD"), "{no_password}");
    let empty = Server::parse("tuic://123e4567-e89b-12d3-a456-426614174000:@t.example:443").unwrap_err();
    assert_eq!(empty, "the password is empty");
    assert!(Server::parse("vless://x@y:1").unwrap_err().starts_with("a line is tuic://"));
}

#[test]
fn a_uuid_of_another_shape_is_refused() {
    for odd in [
        "123e4567-e89b-12d3-a456-42661417400",
        "123e4567e89b-12d3-a456-4266141740000",
        "zz3e4567-e89b-12d3-a456-426614174000",
    ] {
        assert!(Uuid::parse(odd).is_err(), "{odd}");
    }
}
