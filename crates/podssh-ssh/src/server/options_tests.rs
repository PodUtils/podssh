//! The tests of the options of a key line (T-114): the lines of sshd(8)'s
//! examples, OpenSSH's quoting, each option's effect, and each refusal.

use super::*;
use crate::server::authorized::{parse_line, Admission, Authorized, Line};
use crate::server::rules::{from_matches, Asked, Context, Plan};

fn rules(field: &str) -> Rules {
    parse(field).unwrap_or_else(|why| panic!("{field}: {why}"))
}

fn refused(field: &str) -> String {
    parse(field).expect_err(field)
}

fn key_line() -> String {
    let key = crate::keygen::generate(crate::keygen::KeyKind::Ed25519, "t").unwrap();
    key.public_key().to_openssh().unwrap()
}

/// The option fields of sshd(8)'s examples, AUTHORIZED_KEYS FILE FORMAT;
/// the key after each is any key.
#[test]
fn the_examples_of_sshd_8_read_as_sshd_reads_them() {
    let forced = rules(r#"restrict,command="dump /home""#);
    assert_eq!(forced.command.as_deref(), Some("dump /home"));
    assert!(forced.no_pty && forced.no_port_forwarding && forced.no_agent_forwarding && forced.no_x11_forwarding);
    let old = rules(r#"command="dump /home",no-pty,no-port-forwarding"#);
    assert!(old.no_pty && old.no_port_forwarding && !old.no_agent_forwarding);
    let opens = rules(r#"permitopen="192.0.2.1:80",permitopen="192.0.2.2:25""#);
    assert_eq!(
        opens.permit_open,
        vec![Permit { host: "192.0.2.1".into(), port: Some(80) }, Permit { host: "192.0.2.2".into(), port: Some(25) }]
    );
    let game = rules(r#"restrict,pty,command="nethack""#);
    assert!(!game.no_pty, "pty after restrict turns it on again");
    assert!(game.no_port_forwarding);
    assert_eq!(rules("no-touch-required"), Rules::default(), "asks for less than serve checks");
    let from = rules(r#"from="*.sales.example.net,!pc.sales.example.net""#);
    assert_eq!(from.from.as_deref(), Some("*.sales.example.net,!pc.sales.example.net"));
    // The examples that serve cannot honour refuse the line, named.
    for (field, named) in [
        (r#"permitlisten="localhost:8080",permitlisten="[::1]:22000""#, "permitlisten="),
        (r#"tunnel="0",command="sh /etc/netstart tun0""#, "tunnel="),
        ("verify-required", "verify-required"),
        (r#"cert-authority,no-touch-required,principals="user_a""#, "cert-authority"),
        (r#"environment="PATH=/bin:/usr/bin""#, "environment="),
    ] {
        let why = refused(field);
        assert!(why.starts_with(named), "{field}: {why}");
    }
}

#[test]
fn quoting_is_openssh_s() {
    // A quote inside a value, a comma and a blank inside quotes.
    let r = rules(r#"command="echo \"a, b\" c",no-pty"#);
    assert_eq!(r.command.as_deref(), Some(r#"echo "a, b" c"#));
    assert!(r.no_pty);
    // A backslash before anything else stays itself.
    assert_eq!(rules(r#"command="a\\b\n""#).command.as_deref(), Some(r"a\\b\n"));
    assert_eq!(dequote(r#""x\"y" rest"#).unwrap(), (r#"x"y"#.to_string(), " rest"));
    assert!(dequote(r#""never closed"#).is_err());
    assert!(dequote("bare").is_err());
    // The options end at the first blank outside quotes.
    let (field, rest) = split(r#"command="a b",no-pty ssh-ed25519 AAAA c"#).unwrap();
    assert_eq!((field, rest), (r#"command="a b",no-pty"#, "ssh-ed25519 AAAA c"));
    let (field, _) = split(r#"command="say \" b" ssh-ed25519 AAAA"#).unwrap();
    assert_eq!(field, r#"command="say \" b""#, "an escaped quote does not end the quote");
    assert!(split(r#"command="open ssh-ed25519 AAAA"#).is_err());
}

#[test]
fn names_are_in_any_case_and_the_last_flag_wins() {
    let r = rules(r#"NO-PTY,Command="x""#);
    assert!(r.no_pty);
    assert_eq!(r.command.as_deref(), Some("x"));
    assert!(!rules("no-pty,pty").no_pty);
    assert!(rules("pty,no-pty").no_pty);
    assert!(!rules("restrict,port-forwarding").no_port_forwarding);
    assert!(rules("no-agent-forwarding,no-X11-forwarding,no-user-rc").no_x11_forwarding);
}

#[test]
fn a_malformed_or_unknown_option_refuses_the_line() {
    for field in [
        "no-such-option",
        "ptyx",
        "no-pty,",
        "no-pty;restrict",
        r#"command=unquoted"#,
        r#"command="a",command="b""#,
        r#"from="10.0.0.0/33""#,
        r#"from="a",from="b""#,
        r#"expiry-time="2020""#,
        r#"expiry-time="20201301""#,
        r#"permitopen="host""#,
        r#"permitopen="host:0""#,
        r#"permitopen="host:65536""#,
        r#"permitopen="[::1:22""#,
        r#"permitopen=":22""#,
        "touch-required",
    ] {
        assert!(parse(field).is_err(), "{field} must refuse the line");
    }
    let why = refused("no-such-option,no-pty");
    assert!(why.contains("\"no-such-option\""), "the option is named: {why}");
}

#[test]
fn permitopen_takes_brackets_a_slash_and_any_port() {
    let r = rules(r#"permitopen="[::1]:22",permitopen="db/5432",permitopen="cache:*",permitopen="*:443""#);
    let want = |host: &str, port| Permit { host: host.into(), port };
    let wanted = vec![want("::1", Some(22)), want("db", Some(5432)), want("cache", None), want("*", Some(443))];
    assert_eq!(r.permit_open, wanted);
    assert_eq!(r.forward_refusal("::1", 22), None);
    assert_eq!(r.forward_refusal("db", 5432), None);
    assert_eq!(r.forward_refusal("cache", 1), None);
    assert_eq!(r.forward_refusal("anywhere", 443), None);
    let why = r.forward_refusal("db", 5433).expect("refused");
    assert!(why.starts_with("permitopen: db:5433"), "{why}");
    assert!(r.forward_refusal("DB", 5432).is_some(), "the host as written, as OpenSSH compares it");
    assert!(r.forward_refusal("::1", 23).expect("refused").contains("[::1]:23"));
}

#[test]
fn no_port_forwarding_wins_over_permitopen() {
    let r = rules(r#"permitopen="db:5432",no-port-forwarding"#);
    assert!(r.forward_refusal("db", 5432).expect("refused").starts_with("no-port-forwarding"));
    assert_eq!(Rules::default().forward_refusal("anywhere", 1), None);
    assert!(rules("restrict").forward_refusal("db", 1).is_some());
}

#[test]
fn no_pty_and_restrict_refuse_a_pty_with_the_option_named() {
    assert!(rules("no-pty").pty_refusal().expect("refused").starts_with("no-pty"));
    assert!(rules("restrict").pty_refusal().is_some());
    assert_eq!(Rules::default().pty_refusal(), None);
}

#[test]
fn a_forced_command_runs_in_place_of_each_request() {
    let r = rules(r#"command="echo forced""#);
    assert_eq!(r.plan(Asked::Exec(b"ls -l")), Plan::Command(b"echo forced".to_vec(), Some(b"ls -l".to_vec())));
    assert_eq!(r.plan(Asked::Shell), Plan::Command(b"echo forced".to_vec(), None));
    assert_eq!(r.plan(Asked::Sftp), Plan::Command(b"echo forced".to_vec(), Some(b"internal-sftp".to_vec())));
    assert!(matches!(r.plan(Asked::Exec(b"a\0b")), Plan::Refuse(_)));
    let free = Rules::default();
    assert_eq!(free.plan(Asked::Exec(b"ls")), Plan::Command(b"ls".to_vec(), None));
    assert_eq!(free.plan(Asked::Shell), Plan::Shell);
    assert_eq!(free.plan(Asked::Sftp), Plan::Sftp);
}

#[test]
fn a_forced_internal_sftp_serves_sftp_alone() {
    let r = rules(r#"command="internal-sftp""#);
    assert_eq!(r.plan(Asked::Sftp), Plan::Sftp);
    assert!(matches!(r.plan(Asked::Exec(b"ls")), Plan::Refuse(why) if why.contains("SFTP alone")));
    assert!(matches!(r.plan(Asked::Shell), Plan::Refuse(_)));
    let read_only = rules(r#"command="internal-sftp -R""#);
    assert!(matches!(read_only.plan(Asked::Sftp), Plan::Refuse(why) if why.contains("no arguments")));
    let other = rules(r#"command="internal-sftpx""#);
    assert_eq!(other.plan(Asked::Shell), Plan::Command(b"internal-sftpx".to_vec(), None), "a name of its own");
}

#[test]
fn expiry_time_refuses_the_key_after_its_time() {
    let r = rules(r#"expiry-time="20200101Z""#);
    let at = |now| Context { peer: None, now };
    assert_eq!(r.expiry, Some(1_577_836_800));
    assert!(r.admits(&at(1_577_836_800)).is_ok(), "the second named is still in, as in sshd");
    assert!(r.admits(&at(1_577_836_801)).expect_err("expired").starts_with("expiry-time"));
    let two = rules(r#"expiry-time="20300101Z",expiry-time="20200101Z""#);
    assert_eq!(two.expiry, Some(1_577_836_800), "of two, the earlier");
}

#[test]
fn from_matches_addresses_blocks_and_negation() {
    let ip = |s: &str| s.parse().unwrap();
    assert!(from_matches("192.0.2.*", ip("192.0.2.7")));
    assert!(from_matches("10.0.0.0/8,192.0.2.1", ip("10.9.8.7")));
    assert!(!from_matches("10.0.0.0/8,!10.9.0.0/16", ip("10.9.8.7")), "a negated match refuses");
    assert!(from_matches("2001:db8::/32", ip("2001:db8::1")));
    assert!(from_matches("192.0.2.0/24", ip("::ffff:192.0.2.9")), "a mapped address is its IPv4");
    assert!(!from_matches("*.example.net", ip("192.0.2.7")), "serve looks up no name");
    assert!(!from_matches("!192.0.2.7", ip("192.0.2.8")), "a negation alone lets nothing in");
    assert!(from_matches("0.0.0.0/0", ip("203.0.113.1")));
}

#[test]
fn from_with_no_address_never_matches() {
    let r = rules(r#"from="*""#);
    let why = r.admits(&Context { peer: None, now: 0 }).expect_err("no address");
    assert!(why.starts_with("from=") && why.contains("no address"), "{why}");
    assert!(r.admits(&Context { peer: Some("192.0.2.1".parse().unwrap()), now: 0 }).is_ok());
}

#[test]
fn a_whole_line_and_the_first_line_that_admits_holds() {
    let key = key_line();
    let Line::Key(_, r) = parse_line(&format!(r#"command="echo forced",no-pty {key} c"#)) else { panic!("a key") };
    assert_eq!(r.command.as_deref(), Some("echo forced"));
    let Line::Bad(why) = parse_line(&format!("tunnel=\"0\" {key}")) else { panic!("refused") };
    assert!(why.starts_with("tunnel=") && why.contains("not used"), "{why}");
    // An expired line of the key, then one with a forced command.
    let text = format!("expiry-time=\"20200101Z\" {key}\ncommand=\"true\" {key}\n");
    let mut authorized = Authorized::new();
    let read = authorized.add_text_from(&text, "keys");
    assert_eq!((read.added, read.limited), (2, 2), "{read:?}");
    let public = russh::keys::PublicKey::from_openssh(&key).unwrap();
    match authorized.admit(&public, &Context::now(None)) {
        Admission::Admitted(rules) => assert_eq!(rules.command.as_deref(), Some("true")),
        other => panic!("{other:?}"),
    }
    let mut expired = Authorized::new();
    expired.add_text_from(&format!("expiry-time=\"20200101Z\" {key}\n"), "keys");
    match expired.admit(&public, &Context::now(None)) {
        Admission::Refused(why) => assert!(why[0].starts_with("keys, line 1: expiry-time"), "{why:?}"),
        other => panic!("{other:?}"),
    }
}
