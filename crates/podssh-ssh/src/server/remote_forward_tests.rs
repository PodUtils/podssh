//! The refusals of `-R` before any publish, and a teardown that runs once
//! (T-123). The publish and its channels: `tests/serve_remote_forward.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// One case: the settings, the rules or why none, the address, the port,
/// the forwards open, and the words of the refusal or none.
type Case<'a> = (&'a Settings, Result<&'a Rules, &'a String>, &'a str, u32, usize, Option<&'a str>);

/// Each refusal before a publish, one table: forwarding off, a key's
/// rules, a port out of range, an address that is no name, the cap.
#[test]
fn each_refusal_before_a_publish_names_its_reason() {
    let plain = Settings::default();
    let off = Settings { no_forwarding: true, ..Settings::default() };
    let free = Rules::default();
    let closed = Rules { no_port_forwarding: true, ..Rules::default() };
    let none = "no key logged in".to_string();
    let cases: [Case; 8] = [
        (&plain, Ok(&free), "127.0.0.1", 8080, 0, None),
        (&plain, Ok(&free), "", 0, MAX_REMOTE_FORWARDS - 1, None),
        (&off, Ok(&free), "127.0.0.1", 8080, 0, Some("--no-forwarding")),
        (&plain, Ok(&closed), "127.0.0.1", 8080, 0, Some("no-port-forwarding")),
        (&plain, Err(&none), "127.0.0.1", 8080, 0, Some("no key logged in")),
        (&plain, Ok(&free), "127.0.0.1", 65536, 0, Some("past 65535")),
        (&plain, Ok(&free), "a\nb", 80, 0, Some("no host name")),
        (&plain, Ok(&free), "127.0.0.1", 80, MAX_REMOTE_FORWARDS, Some("forwards are open")),
    ];
    for (settings, rules, address, port, open, want) in cases {
        let got = refusal(settings, rules, address, port, open);
        match (got.as_deref(), want) {
            (None, None) => {}
            (Some(why), Some(words)) => assert!(why.contains(words), "{address}:{port}: {why}"),
            (got, want) => panic!("{address}:{port}: {got:?}, wanted {want:?}"),
        }
    }
}

/// A forward's teardown runs once, when it leaves: by a cancel, or by the
/// end of its connection; a cancel of one that is not there is false.
#[test]
fn a_teardown_runs_once_as_its_forward_leaves() {
    static STOPPED: AtomicUsize = AtomicUsize::new(0);
    let published = |port| Published {
        name: format!("p-{port}"),
        port,
        stop: Stop::new(|| {
            STOPPED.fetch_add(1, Ordering::SeqCst);
        }),
    };
    let mut forwards = Forwards::default();
    forwards.live.insert(("127.0.0.1".into(), 1), published(1));
    forwards.live.insert(("127.0.0.1".into(), 2), published(2));
    assert!(forwards.cancel("127.0.0.1", 1));
    assert_eq!(STOPPED.load(Ordering::SeqCst), 1);
    assert!(!forwards.cancel("127.0.0.1", 1), "a second cancel finds nothing");
    assert_eq!(STOPPED.load(Ordering::SeqCst), 1, "and stops nothing twice");
    assert_eq!(forwards.len(), 1);
    drop(forwards);
    assert_eq!(STOPPED.load(Ordering::SeqCst), 2, "the connection's end stops the rest");
    drop(Stop::nothing());
}
