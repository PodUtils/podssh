//! The URI, the credential file and the time of a Refresh. The road
//! against a stand-in TURN server is `tests/turn.rs`, and against coturn
//! `crates/podssh-cli/tests/turn_road.rs` with turn-interop.yml.

use super::*;

#[test]
fn a_server_is_rfc_7065_s_uri_with_443_for_turns() {
    let s = Server::parse("turns:turn.example.org").unwrap();
    assert_eq!((s.tls, s.host.as_str(), s.port), (true, "turn.example.org", 443));
    assert_eq!(s.shown(), "turns:turn.example.org");
    let s = Server::parse("turn:[2001:db8::1]:3479?transport=tcp").unwrap();
    assert_eq!((s.tls, s.host.as_str(), s.port), (false, "2001:db8::1", 3479));
    assert_eq!(s.shown(), "turn:[2001:db8::1]:3479");
    assert_eq!(Server::parse("TURN:h.example").unwrap().port, 3478);
    assert!(Server::parse("turns://h.example").unwrap_err().contains("no //"));
    assert!(Server::parse("turns:h.example?transport=udp").unwrap_err().contains("UDP"));
    assert!(Server::parse("turns:u:p@h.example").unwrap_err().contains("--turn-auth-file"));
    assert!(Server::parse("stun:h.example").unwrap_err().contains("no TURN URI"));
    assert!(Server::parse("turns:h.example:0").is_err());
}

#[test]
fn turn_with_no_tls_goes_only_to_this_host() {
    assert!(check(&Server::parse("turn:127.0.0.1").unwrap()).is_ok());
    assert!(check(&Server::parse("turn:h.example").unwrap()).unwrap_err().contains("give turns:"));
    assert!(check(&Server::parse("turns:h.example").unwrap()).is_ok());
}

#[test]
fn the_file_gives_a_user_and_password_or_a_secret_and_never_shows_them() {
    let c = Credentials::parse("# mine\nalice:pa:ss\n").unwrap();
    let (user, password) = c.pair();
    assert_eq!((user.as_str(), password.as_str()), ("alice", "pa:ss"));
    assert!(!format!("{c:?}").contains("pa:ss"));
    let s = Credentials::parse("auth-secret n0rth\n").unwrap();
    assert!(matches!(&s, Credentials::Secret(v) if v.as_str() == "n0rth"));
    assert!(s.pair().0.ends_with(":podssh"));
    let bad = Credentials::parse("\nno-colon-s3cret\n").unwrap_err();
    assert!(bad.starts_with("line 2:") && !bad.contains("s3cret"), "{bad}");
    assert!(Credentials::parse("a:b\nc:d\n").unwrap_err().contains("one line"));
    assert!(Credentials::parse(":b\n").is_err());
}

#[test]
fn a_refresh_comes_a_minute_early_or_at_half_a_short_lifetime() {
    assert_eq!(keep::refresh_after(600), Duration::from_secs(540));
    assert_eq!(keep::refresh_after(60), Duration::from_secs(30));
    assert_eq!(keep::refresh_after(4), Duration::from_secs(5));
}
