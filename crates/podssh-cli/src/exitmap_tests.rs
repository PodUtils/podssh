//! The fault table's checks: the codes, the collisions that are declared, the
//! split of a close by its reason and by `established`.

use super::*;
use crate::man::data::{exit_codes as manual, Code};

/// **THE DECISION, asserted.** This is the check that fails if somebody
/// re-types `2` into this crate, and it is the test the two agents who
/// flagged the fork needed.
#[test]
fn a_usage_error_is_sixty_four() {
    assert_eq!(code(Fault::Usage), 64);
    // Not 2. This assertion exists so that reverting to 2 breaks the
    // suite loudly instead of silently re-creating the collision.
    assert_ne!(code(Fault::Usage), 2);
    assert_eq!(code(Fault::Usage), sysexits::EX_USAGE);
}

/// **The whole reason `Usage` is 64: it is the only row a script needs
/// to be certain of.** `2` is what a bare `test`, a `grep` miss and a
/// `diff` disagreement already return, so a status of `2` from any program
/// is not evidence of anything; `64` is.
#[test]
fn usage_does_not_collide_with_a_shell_status() {
    for shell_status in [1, 2] {
        assert_ne!(code(Fault::Usage), shell_status);
        for (fault, _) in TABLE {
            assert_ne!(code(*fault), shell_status, "{} uses a shell status", fault.name());
        }
    }
}

/// **`Config` moved off `2`.** That promotion is the whole of what `2`
/// losing amounts to, so it is asserted directly.
#[test]
fn config_is_no_longer_two() {
    assert_eq!(code(Fault::Config), sysexits::EX_CONFIG);
    assert_ne!(code(Fault::Config), 2);
}

/// **`TABLE` and [`code`] cannot disagree.** A row edited without the
/// match arm is a table that lies to each reader of it.
#[test]
fn table_agrees_with_code() {
    for (fault, expected) in TABLE {
        assert_eq!(code(*fault), *expected, "{} disagrees with TABLE", fault.name());
        assert_ne!(*expected, 0, "{} would exit 0", fault.name());
    }
}

/// **THE COLLISION GUARD, and it is planted in both directions.** Every
/// pair sharing a code must appear in [`SHARED_CODES`], and every declared
/// pair must actually share one — so neither a new accidental collision
/// nor a stale justification passes.
#[test]
fn no_undeclared_code_collisions() {
    for (i, &(a, ca)) in TABLE.iter().enumerate() {
        for &(b, cb) in &TABLE[i + 1..] {
            if ca != cb {
                continue;
            }
            let declared = SHARED_CODES
                .iter()
                .any(|(c, names)| *c == ca && names.contains(&a.name()) && names.contains(&b.name()));
            assert!(declared, "{} and {} both exit {} and SHARED_CODES does not say why", a.name(), b.name(), ca);
        }
    }
    for (code_value, names) in SHARED_CODES {
        for name in *names {
            let row = TABLE.iter().find(|(f, _)| f.name() == *name);
            assert!(row.is_some(), "SHARED_CODES names {name}, which TABLE does not");
            assert_eq!(row.unwrap().1, *code_value, "SHARED_CODES claims {name} exits {code_value}, TABLE disagrees");
        }
    }
}

/// **A fault cannot exist without a name.** Each variant has one in
/// [`Fault::name`], and no variant returns an empty string.
#[test]
fn every_fault_has_a_name() {
    for (fault, _) in TABLE {
        assert!(!fault.name().is_empty());
    }
}

/// **The two `1001` rows demand opposite actions, so the REASON decides.**
/// The relay's table "Reverse close codes": `operator stopped reverse relay` against `pair
/// expired`. A new pair, against a pair that is gone.
#[test]
fn a_1001_is_split_by_its_reason_not_its_code() {
    let revoked = Fault::from_close(1001, "operator stopped reverse relay", true);
    let expired = Fault::from_close(1001, "pair expired", true);
    assert_ne!(revoked, expired);
    assert_ne!(code(revoked), code(expired));
    assert_eq!(code(revoked), sysexits::EX_UNAVAILABLE);
    assert_eq!(code(expired), sysexits::EX_NOPERM);
}

/// **The sibling's defect #1, restated as a test.** `dropssh`
/// `src/connect.c:455-461` assigns no `rc` on `1003`/`1009` and returns 0.
#[test]
fn a_post_ready_fault_is_never_zero() {
    for close in [1003u16, 1008, 1009, 1011, 1013] {
        let f = Fault::from_close(close, "bad multiplex frame", true);
        assert_ne!(code(f), 0, "close {close} reported success");
        assert_eq!(f, Fault::SessionFault);
    }
}

/// **`established` decides before the close code.** The close code is
/// identical in both rows and the outcome is not.
///
/// **Two faults, two codes — and the difference is what the test first
/// got wrong.** `1000` before `ready` is a session that never existed, and
/// `1000` after it is a session that ended without delivering a status.
/// They are `SessionFault` and `ChannelClosed`, so they read 70 and 70.
/// **A collision with a declared reason, not an accident** — and the
/// declaration is the thing that makes reading the code enough to know
/// which case this is.
#[test]
fn established_decides_before_the_close_code() {
    let before = Fault::from_close(1000, "", false);
    let after = Fault::from_close(1000, "", true);
    assert_ne!(before, after);
    assert_ne!(code(before), 0);
    // And the two codes are the same sysexits value on purpose — see
    // SHARED_CODES. **Asserting they differ is what the first version of
    // this test did, and it was the test that was wrong**: the fault is
    // the same class either way, so demanding two numbers manufactures a
    // fake distinction. The distinction that matters is the FAULT, and
    // the two lines above assert it.
    assert_eq!(code(before), sysexits::EX_SOFTWARE);
    assert_eq!(code(after), sysexits::EX_SOFTWARE);
}

/// **The clean close that is a FAULT, which is the exit-code table's first trap.** A
/// `1000` before `ready` reads as a normal closure and the session never
/// worked. It must not be 0, and it must not be the clean-close row.
#[test]
fn a_clean_close_before_ready_is_a_fault_and_not_a_clean_close() {
    let f = Fault::from_close(1000, "", false);
    assert_ne!(code(f), 0);
    assert_eq!(f, Fault::SessionFault);
    assert_ne!(f, Fault::ChannelClosed);
    assert_ne!(f, Fault::Remote(0));
}

/// **A truncation is `SessionFault`, never `ChannelClosed`.** Plant 7's
/// defect is a silent 0; a row that mapped a truncated tail onto the clean
/// close would reintroduce it with a different number in front of it.
#[test]
fn a_truncated_tail_is_never_the_clean_close_row() {
    // The channel dies with no exit-status: the close never arrived at all.
    let truncated = Fault::from_close(1009, "session byte cap", true);
    assert_eq!(truncated, Fault::SessionFault);
    assert_ne!(truncated, Fault::ChannelClosed);
    assert_ne!(code(truncated), 0);
}

/// **`established_sensitive` is the predicate the caller needs, and it
/// must be true of both rows the `1000` split produces.** **This is the
/// test that pins what that method means**, because **a method that
/// answers `false` for a row that genuinely depends on `established` is the
/// bug it was written to prevent** — and it was **wrong in the first
/// version of this file**, which returned `true` for one of the two.
#[test]
fn both_rows_of_the_1000_split_depend_on_established() {
    for established in [false, true] {
        let f = Fault::from_close(1000, "", established);
        assert!(f.established_sensitive(), "{f:?} at established={established} does not depend on established");
    }
    // And a fault that happens before any session exists does not.
    for f in [Fault::Usage, Fault::Auth, Fault::Revoked, Fault::Config] {
        assert!(!f.established_sensitive(), "{f:?} cannot depend on a session that never opened");
    }
}

/// **`Remote(0)` is the only legitimate zero.** Plant 7 is a channel that
/// closes with no `exit-status`; that is `ChannelClosed`, and it is 70.
#[test]
fn only_a_delivered_status_reaches_zero() {
    assert_eq!(code(Fault::Remote(0)), 0);
    assert_eq!(code(Fault::Remote(7)), 7);
    // The truncated tail: the silent-success bug.
    assert_ne!(code(Fault::ChannelClosed), 0);
    assert_ne!(code(Fault::SessionFault), 0);
}

/// **A remote `127` is propagated verbatim.** A script seeing 127 on
/// `ssh host cmd` means "command not found on the remote", and remapping
/// it onto a fault code destroys that.
#[test]
fn a_remote_127_is_not_remapped_onto_a_fault() {
    for (fault, _) in TABLE {
        assert_ne!(code(Fault::Remote(127)), code(*fault), "{} ate a remote 127", fault.name());
    }
}

/// **The fork is closed, asserted so that reopening it is a deliberate act.**
/// Before 2026-10-06 this test asserted `Some((64, 2))` — the open fork —
/// and was written to FAIL the moment `EXIT_USAGE` became 64. The flip has
/// landed, so it now asserts `None`: the table's value and what the binary
/// emits agree. If they ever disagree again, this fails and names both sides.
#[test]
fn the_usage_fork_is_closed() {
    assert_eq!(
        usage_fork(),
        None,
        "the fork reopened: EXIT_USAGE in exit_codes.rs disagrees with \
         sysexits::EX_USAGE (64); see docs/decisions.md (exit codes)"
    );
}

/// **pod-core's code where the two agree, the manual's code always** (T-820).
/// Each row of [`TABLE`] is a row of the manual's EXIT STATUS. A fault that
/// takes its class's code gets that number; a fault that keeps its own names
/// the class whose code differs, so a class that comes to agree is taken, not
/// kept by habit, and a fault with no class has no class of that number.
#[test]
fn each_fault_takes_pod_core_s_code_where_they_agree_and_the_manual_s_always() {
    let documented: Vec<i32> = manual()
        .into_iter()
        .filter_map(|(code, _)| match code {
            Code::Value(n) => Some(n),
            Code::Remote => None,
        })
        .collect();
    let of = |class: Class| i32::from(class.exit_code());
    for &(fault, code) in TABLE {
        let name = fault.name();
        assert!(documented.contains(&code), "{name}: {code} is not in the manual's EXIT STATUS");
        assert_eq!(fault.code(), code, "{name}");
        match fault.origin() {
            Origin::Pod(class) => {
                assert_eq!(of(class), code, "{name} takes pod-core's {class}");
                assert_eq!(fault.class(), Some(class), "{name}");
            }
            Origin::Own { code: own, nearest: Some(class) } => {
                assert_eq!(own, code, "{name}");
                assert_ne!(of(class), code, "{name}: pod-core's {class} gives {code} now; take it");
            }
            Origin::Own { code: own, nearest: None } => {
                assert_eq!(own, code, "{name}");
                let same = Class::ALL.into_iter().find(|c| of(*c) == code);
                assert_eq!(same, None, "{name}: a class of pod-core gives {code}; is it this fault's?");
            }
        }
    }
    // A remote status is the remote's: no class, and its number unchanged.
    assert_eq!(Fault::Remote(127).class(), None);
    assert_eq!(Fault::Remote(127).origin(), Origin::Own { code: 127, nearest: None });
}

/// **Each `sysexits` value that a class of pod-core has is that class's
/// code.** The values stay `const` (patterns and other constants read them,
/// and `Class::exit_code` is no `const fn`), so this holds them to the crate.
#[test]
fn each_sysexits_value_is_pod_core_s_where_a_class_has_it() {
    let rows: [(i32, Option<Class>); 9] = [
        (sysexits::EX_USAGE, Some(Class::Usage)),
        (sysexits::EX_DATAERR, None),
        (sysexits::EX_NOINPUT, Some(Class::NotFound)),
        (sysexits::EX_UNAVAILABLE, Some(Class::Unavailable)),
        (sysexits::EX_SOFTWARE, None),
        (sysexits::EX_CANTCREAT, None),
        (sysexits::EX_TEMPFAIL, Some(Class::TempFail)),
        (sysexits::EX_NOPERM, Some(Class::Refused)),
        (sysexits::EX_CONFIG, Some(Class::Config)),
    ];
    for (code, class) in rows {
        let same = Class::ALL.into_iter().find(|c| i32::from(c.exit_code()) == code);
        match class {
            Some(class) => assert_eq!(i32::from(class.exit_code()), code, "{class}"),
            None => assert_eq!(same, None, "{code}: a class of pod-core gives it now"),
        }
    }
}
