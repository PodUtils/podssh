//! The verdicts of `--tier` from planted facts, and the table of what each
//! closed capability closes. Pure: no probe runs here.

use super::*;

fn floor(ran: Option<&str>, refused: usize, untried: usize) -> Floor {
    let mut f = Floor::default();
    if let Some(dir) = ran {
        f.ran(dir.to_string());
    }
    (0..refused).for_each(|_| f.closed());
    (0..untried).for_each(|_| f.unknown());
    f
}

fn reasons(call: &Call) -> Vec<Reason> {
    match call {
        Call::Closed(r, _) => r.clone(),
        _ => Vec::new(),
    }
}

/// The table cannot drift: each verb and flag that it names is in the flag
/// table, and each reason has a row, each row a reason.
#[test]
fn every_gated_feature_names_a_verb_and_a_flag_that_exist() {
    for (reason, features) in CLOSES {
        assert!(!features.is_empty(), "{reason:?} closes nothing");
        for f in *features {
            let verb = crate::flags::verb_for(f.verb).unwrap_or_else(|| panic!("{reason:?}: no verb {}", f.verb));
            if let Some(flag) = f.flag {
                assert!(verb.flags.iter().any(|r| r.long == flag), "{reason:?}: {} has no --{flag}", f.verb);
            }
            assert!(!f.what.is_empty(), "{reason:?}: {} has no words", f.verb);
        }
    }
}

#[test]
fn every_reason_has_one_row_and_every_row_a_reason() {
    for reason in Reason::ALL {
        let rows = CLOSES.iter().filter(|(r, _)| *r == reason).count();
        assert_eq!(rows, 1, "{reason:?} has {rows} rows in CLOSES");
    }
    assert_eq!(CLOSES.len(), Reason::ALL.len());
    // Each category is closed by at least one reason, so none is a dead word.
    assert_eq!(Rung::ALL.len(), 5);
}

#[test]
fn each_closed_reason_says_what_it_closes() {
    for reason in Reason::ALL {
        assert!(closed_words(&[reason]).starts_with("podssh "), "{reason:?}");
    }
    assert!(closed_words(&[Reason::NoExecDir]).contains("podssh session --detach"));
    assert_eq!(closed_words(&[]), "");
}

#[test]
fn identity_is_ok_closed_or_unread() {
    let named = Name::Entry("ada".into());
    assert!(matches!(identity(&named, Some(true)), Call::Ok(_)));
    assert!(matches!(identity(&Name::Root, Some(true)), Call::Ok(_)));
    assert!(matches!(identity(&Name::Variable("USER=ada".into()), Some(true)), Call::Ok(_)));
    assert_eq!(reasons(&identity(&Name::Missing(1000), Some(true))), [Reason::NoUserName]);
    assert_eq!(reasons(&identity(&named, Some(false))), [Reason::NoBindCapability]);
    let both = identity(&Name::Missing(1000), Some(false));
    assert_eq!(reasons(&both), [Reason::NoUserName, Reason::NoBindCapability]);
}

/// `????` never counts as ok: an unread set or user is not a held capability.
#[test]
fn an_unread_fact_is_never_ok() {
    assert!(matches!(identity(&Name::Entry("ada".into()), None), Call::Unknown(_)));
    assert!(matches!(identity(&Name::Unread("EIO".into()), Some(true)), Call::Unknown(_)));
    assert!(matches!(identity(&Name::NotProbed, Some(true)), Call::Unknown(_)));
    assert!(matches!(terminal(&Pty::NotProbed), Call::Unknown(_)));
    assert!(matches!(state(&State::NotProbed), Call::Unknown(_)));
    assert!(matches!(exec(&Floor::default()), Call::Unknown(_)), "no directory tried");
    assert!(matches!(exec(&floor(None, 2, 1)), Call::Unknown(_)), "one try did not end");
    assert!(matches!(resolver(&Resolver::Unknown("offline".into())), Call::Unknown(_)));
    // A closed fact beside an unread one is still closed: it is known.
    assert!(matches!(identity(&Name::Missing(7), None), Call::Closed(..)));
}

#[test]
fn exec_reports_the_path_probe_only() {
    assert!(matches!(exec(&floor(Some("/tmp"), 1, 1)), Call::Ok(d) if d.contains("/tmp")));
    assert_eq!(reasons(&exec(&floor(None, 3, 0))), [Reason::NoExecDir]);
}

#[test]
fn terminal_and_state_close_on_their_probe() {
    assert!(matches!(terminal(&Pty::Allocates("/dev/pts/3".into())), Call::Ok(_)));
    assert_eq!(reasons(&terminal(&Pty::Closed("/dev/ptmx: ENOENT".into()))), [Reason::NoPty]);
    assert!(matches!(state(&State::Writes("/home/ada/.cache/podssh".into())), Call::Ok(_)));
    assert_eq!(reasons(&state(&State::Closed("none".into()))), [Reason::NoStateDir]);
}

#[test]
fn the_resolver_is_one_class() {
    for class in [
        Resolver::Proxy,
        Resolver::Pins(2),
        Resolver::System("192.0.2.1".into()),
        Resolver::Cache(1),
        Resolver::Doh("1.1.1.1".into()),
    ] {
        assert!(matches!(resolver(&class), Call::Ok(_)), "{class:?}");
    }
    assert_eq!(reasons(&resolver(&Resolver::Unresolved("no".into()))), [Reason::NoResolver]);
}

fn run(facts: &Facts, class: &Resolver, json: bool) -> (i32, String) {
    let mut out = Vec::new();
    let code = {
        let mut report = Report::new(&mut out);
        report.json = json;
        show(&mut report, &compose(facts, class));
        report.finish()
    };
    (code, String::from_utf8(out).unwrap())
}

fn open() -> Facts {
    Facts {
        name: Name::Entry("ada".into()),
        bind: Some(true),
        floor: floor(Some("/tmp"), 0, 0),
        pty: Pty::Allocates("/dev/pts/1".into()),
        state: State::Writes("/home/ada/.cache".into()),
    }
}

#[test]
fn a_closed_capability_names_its_features_and_never_fails_the_run() {
    let mut facts = open();
    facts.floor = floor(None, 2, 0);
    facts.pty = Pty::Closed("/dev/ptmx: no such file".into());
    let (code, text) = run(&facts, &Resolver::System("192.0.2.1".into()), false);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("closed exec"), "{text}");
    assert!(text.contains("unavailable because of this: podssh session --detach"), "{text}");
    assert!(text.contains("closed terminal"), "{text}");
    assert!(text.contains("ok     identity"), "{text}");
    assert!(text.contains("3 of 5 capabilities open, 2 closed, 0 ????"), "{text}");
    // The counts are those of checks: two ok lines, and the closed two are no check.
    assert!(text.contains("3 ok, 0 FAIL, 0 ????"), "{text}");
}

#[test]
fn an_unread_category_counts_as_unknown_and_json_has_the_words() {
    let (code, text) = run(&Facts::default(), &Resolver::Unknown("PODSSH_OFFLINE is set".into()), false);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("????   exec"), "{text}");
    assert!(!text.contains("  closed "), "{text}");
    let (_, json) = run(&open(), &Resolver::Unresolved("nothing answers".into()), true);
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    let status = |check: &str| {
        let line = doc["checks"].as_array().unwrap().iter().find(|c| c["check"] == check).unwrap();
        line["status"].as_str().unwrap().to_string()
    };
    assert_eq!(status("resolver"), "closed");
    assert_eq!(status("identity"), "ok");
    assert_eq!(status("verdict"), "closed");
    assert_eq!(doc["counts"]["fail"], 0);
}
