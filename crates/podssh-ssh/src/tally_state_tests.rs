//! The state word of each forward (T-840), as `~#` lists it. The names of
//! these tests start with `escape_` so that the Prove's filter takes them.

use super::*;

/// Each change of state from one table: what it was, what is set with which
/// reason, whether that is a change, and the word that `~#` then shows.
#[test]
fn escape_list_each_change_of_state_has_one_rule() {
    type Step = (State, Option<&'static str>, bool, &'static str);
    let steps: &[Step] = &[
        // A new forward is bound, so the same word is no change.
        (State::Bound, None, false, "bound"),
        (State::Up, None, true, "up"),
        // Each connection of `-L` says up again: no change, no line.
        (State::Up, None, false, "up"),
        (State::Waiting, None, true, "waiting"),
        (State::Waiting, None, false, "waiting"),
        // A reason outside a refusal is not kept.
        (State::Up, Some("ignored"), true, "up"),
        (State::Refused, Some("administratively prohibited"), true, "refused (administratively prohibited)"),
        (State::Refused, Some("administratively prohibited"), false, "refused (administratively prohibited)"),
        // Another reason is a change; none is said as the bare word.
        (State::Refused, Some("unknown channel type"), true, "refused (unknown channel type)"),
        (State::Refused, None, true, "refused"),
        (State::Refused, Some(""), false, "refused"),
        (State::Up, None, true, "up"),
    ];
    let word = Word::default();
    assert_eq!(word.get(), State::Bound, "a new forward claims least");
    for (n, &(state, reason, changed, shown)) in steps.iter().enumerate() {
        assert_eq!(word.set(state, reason), changed, "step {n}: {state:?} {reason:?}");
        assert_eq!((word.get(), word.shown().as_str()), (state, shown), "step {n}");
        if state != State::Refused {
            assert_eq!(word.reason(), None, "step {n}: a reason outside a refusal");
        }
    }
}

/// Each number reads back as its state, and an unknown one as `bound`; each
/// word is distinct.
#[test]
fn escape_list_words_and_numbers() {
    for (n, state) in State::ALL.iter().enumerate() {
        assert_eq!(State::of(n as u8), *state);
    }
    assert_eq!(State::of(200), State::Bound);
    let words: Vec<&str> = State::ALL.iter().map(|s| s.word()).collect();
    assert_eq!(words, ["bound", "waiting", "up", "refused"]);
}

/// A reason is one bounded line: no peer's words forge a second line.
#[test]
fn escape_list_a_reason_is_one_bounded_line() {
    let word = Word::default();
    word.set(State::Refused, Some("no\r\nForwarding port.\x1b[2J"));
    let shown = word.shown();
    assert!(!shown.chars().any(char::is_control), "{shown:?}");
    assert_eq!(shown, "refused (no  Forwarding port. [2J)");
    word.set(State::Refused, Some(&"é".repeat(REASON_MAX + 50)));
    let reason = word.reason().unwrap();
    assert_eq!(reason.chars().count(), REASON_MAX + 3, "bounded, on a character's edge");
    assert!(reason.ends_with("..."));
}

/// The line of a change names the forward, its word, and the loss after it.
#[test]
fn escape_list_the_line_of_a_change() {
    assert_eq!(line("-L 8080:db:5432", "up", None), "-L 8080:db:5432: up");
    let lost = "connection to web lost: reset";
    assert_eq!(line("-R 9000:localhost:80", "waiting", Some(lost)), format!("-R 9000:localhost:80: waiting: {lost}"));
}

/// `~#` gives each forward its word after its counts; a lost link makes
/// each open forward wait, and one that `~C` stopped stays `closed`.
#[test]
fn escape_list_tilde_hash_says_each_state() {
    let up = "-L escape-state-test:1";
    let refused = "-R escape-state-test:2";
    let stopped = "-L escape-state-test:3";
    crate::tally::of(up).set_state(up, State::Up, None, None);
    crate::tally::of(refused).set_state(refused, State::Refused, Some("administratively prohibited"), None);
    crate::tally::of(stopped).set_state(stopped, State::Up, None, None);
    crate::tally::closed(stopped);
    let listing = crate::tally::listing();
    let of = |name: &str| listing.lines().find(|l| l.trim_start().starts_with(&format!("{name}: "))).unwrap_or("");
    assert!(of(up).ends_with(" bytes down; up"), "{listing}");
    assert!(of(refused).ends_with("; refused (administratively prohibited)"), "{listing}");
    assert!(of(stopped).ends_with("; closed"), "{listing}");

    // The loss of this test's forwards alone: the table is the process's,
    // and the tests beside this one read theirs.
    let mine: Vec<(String, std::sync::Arc<crate::tally::Counts>)> =
        [up, refused, stopped].iter().map(|n| (n.to_string(), crate::tally::of(n))).collect();
    crate::tally::wait_each(&mine, "the connection to escape.test was lost");
    let lines = crate::tally::lines();
    let of = |name: &str| lines.iter().find(|l| l.starts_with(&format!("{name}: "))).cloned().unwrap_or_default();
    assert!(of(up).ends_with("; waiting"), "{lines:?}");
    assert!(of(refused).ends_with("; waiting"), "a refused one is asked again: {lines:?}");
    assert!(of(stopped).ends_with("; closed"), "{lines:?}");
    let snapshot = crate::tally::snapshots().into_iter().find(|f| f.name == stopped).expect("listed");
    assert!(snapshot.closed && snapshot.reason.is_none(), "{snapshot:?}");
    // The result file's word is the listing's (T-866): `closed`, not the state under it.
    assert_eq!(snapshot.word(), "closed", "{snapshot:?}");
    let open = crate::tally::snapshots().into_iter().find(|f| f.name == up).expect("listed");
    assert_eq!(open.word(), open.state.word(), "{open:?}");
}
