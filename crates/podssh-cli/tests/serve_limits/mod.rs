//! The limits of `podssh relay serve` that its flags move (T-704, GitHub
//! #169): `/relays.json` publishes the values in force, a bad value is a
//! usage refusal.

#![cfg(unix)]

use crate::throughput_harness::Session;
use crate::{ran, relay_flags, role, said};

// T-704: the limits that the flags move are published in /relays.json, which
// `relay info` prints, and a bad value is a usage refusal (64).
#[test]
fn the_limit_flags_are_published_in_relays_json_and_a_bad_one_is_refused() {
    let s = Session::start("serve-limits");
    let Some(cell) = role(
        &s,
        &["--idle", "5", "--session-hours", "2", "--max-session-mib", "8", "--connect", "3", "--keepalive", "2"],
    ) else {
        return;
    };
    let mut args = vec!["relay".to_string(), "info".into(), "github.com".into(), "22".into()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("limits: connect 3 s, idle 5 s, a session 2 h, a session 8 MiB"),
        "the limits in force, not the compiled ones: {text}"
    );
    assert!(!text.contains("keepalive"), "the keepalive is no field of the contract: {text}");
    let bad = [
        ("--idle", "0"),
        ("--idle", "86401"),
        ("--session-hours", "169"),
        ("--max-session-mib", "4097"),
        ("--connect", "121"),
        ("--keepalive", "x"),
    ];
    for (flag, value) in bad {
        let args = ["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", flag, value];
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let out = ran(s.command(&args));
        assert_eq!(out.status.code(), Some(64), "{flag} {value}: {}", said(&out));
        assert!(said(&out).contains(&format!("{flag} {value:?}: ")), "{flag} {value}: {}", said(&out));
    }
    let args: Vec<String> = ["relay", "status", "--idle", "5"].iter().map(|a| a.to_string()).collect();
    let out = ran(s.command(&args));
    assert_eq!(out.status.code(), Some(64), "{}", said(&out));
    assert!(said(&out).contains("go with `podssh relay serve` only"), "{}", said(&out));
}

// The cuts themselves, the idle one and the byte cap, are the role's: they
// are tested on a raw socket in podssh-relay's `relay_serve_limits` and
// `http_road`, as podssh's own client carries a session past a cut.
