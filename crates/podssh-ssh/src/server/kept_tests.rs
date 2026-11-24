use std::time::{Duration, Instant};

use pod_term::grammar::Ring;

use super::super::kept_ask::with_id;
use super::{since, Asked};

/// Each `env` request of podssh's own and its values: one rule for the
/// family, a good value taken and a bad one refused; another name is the
/// client's own variable.
#[test]
fn the_requests_of_the_kept_shells_take_good_values_only() {
    let longest = "x".repeat(32);
    let cases: &[(&str, &str, Option<bool>)] = &[
        ("attach@podssh", "work", Some(true)),
        ("attach@podssh", longest.as_str(), Some(true)),
        ("attach@podssh", "../x", Some(false)),
        ("attach@podssh", "", Some(false)),
        ("keep@podssh", "build-2", Some(true)),
        ("keep@podssh", "a b", Some(false)),
        ("from@podssh", "0123456789abcdef0123456789abcdef", Some(true)),
        ("from@podssh", "", Some(false)),
        ("take@podssh", "yes", Some(true)),
        ("lease@podssh", "60", Some(true)),
        ("lease@podssh", "0", Some(false)),
        ("lease@podssh", "2592001", Some(false)),
        ("lease@podssh", "an hour", Some(false)),
        ("LANG", "C.UTF-8", None),
        ("detach@podssh", "work", None),
    ];
    for (name, value, want) in cases {
        let mut asked = Asked::default();
        assert_eq!(asked.note(name, value), *want, "{name}={value:?}");
    }
    let mut asked = Asked::default();
    asked.note("attach@podssh", "work");
    asked.note("take@podssh", "yes");
    asked.note("lease@podssh", "90");
    assert_eq!(asked.attach.as_deref(), Some("work"));
    assert!(asked.take);
    assert_eq!(asked.lease, Some(Duration::from_secs(90)));
    let too_long = "x".repeat(65);
    assert_eq!(Asked::default().note("from@podssh", &too_long), Some(false));
}

/// What an attach gets of the ring: the bytes since its offset; past what
/// the ring holds, its bytes from its first boundary and the count lost.
#[test]
fn an_attach_gets_the_bytes_since_its_offset_or_says_what_was_lost() {
    let now = Instant::now();
    let mut ring = Ring::new(16);
    ring.push(b"hello ", now);
    assert_eq!(since(&ring, 0), (b"hello ".to_vec(), 0));
    assert_eq!(since(&ring, 2), (b"llo ".to_vec(), 0));
    assert_eq!(since(&ring, 6), (Vec::new(), 0), "nothing new");
    assert_eq!(since(&ring, 60), (Vec::new(), 0), "past the end");
    ring.push(b"world, and more", now);
    let start = ring.start().expect("text is at a boundary");
    assert!(start > 0, "the ring dropped its oldest bytes");
    let (bytes, lost) = since(&ring, 0);
    assert_eq!(lost, start, "the bytes before the ring's first are lost");
    assert_eq!(bytes, ring.kept());
    let (bytes, lost) = since(&ring, start + 1);
    assert_eq!((bytes.len() as u64, lost), (ring.end() - start - 1, 0));
}

/// The shell's id is in its environment once, in the place of any that
/// the client sent.
#[test]
fn the_shell_id_is_set_once() {
    let env = vec![("PODSSH_SHELL_ID".into(), "theirs".into()), ("PATH".into(), "/bin".into())];
    let env = with_id(env, "ours");
    let ids: Vec<_> = env.iter().filter(|(k, _)| k == "PODSSH_SHELL_ID").map(|(_, v)| v.clone()).collect();
    assert_eq!(ids, vec![std::ffi::OsString::from("ours")]);
    assert_eq!(env.len(), 2);
}
