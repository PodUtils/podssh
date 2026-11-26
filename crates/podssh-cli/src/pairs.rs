//! The stored pairs of the reverse road, as `podssh node` and `podssh relay`
//! use them: the pair under a label, or a refusal that names the remedy; the
//! exit code of each failure, by the table of `exitmap`; the trust store; and
//! an expiry in UTC. No message holds a token.

use std::path::Path;

use podssh_relay::pair::{self, Pair, PairContext, PairError};
use podssh_relay::{context::Context, relay::Relay};
use podssh_ws::client::ConnectError;
use podssh_ws::dial::DialError;
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

/// Bound on each request to the relay's control host.
pub(crate) const REQUEST_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Milliseconds since the Unix epoch, now: the process's clock, the role's too (T-710).
pub(crate) fn now_ms() -> i64 {
    podssh_relay::clock::now_ms()
}

/// `2026-10-12T08:10:00Z`, for milliseconds since the epoch.
pub(crate) fn utc(ms: i64) -> String {
    crate::doctor::clock::format_utc(ms.div_euclid(1000))
}

/// A label that the store takes, or a usage error that says why.
pub(crate) fn check_label(label: &str) -> Result<(), Refusal> {
    pair::file_name(label).map(|_| ()).map_err(|e| Refusal::usage(label_words(&e.to_string())))
}

/// The crate's words of a label, said once (T-949): it puts "the label"
/// before pod-core's "the pair name is empty".
fn label_words(said: &str) -> String {
    said.replacen("the label the pair name ", "the label ", 1)
}

/// The pair stored under `label`, if it has not expired.
pub(crate) fn stored(label: &str) -> Result<Pair, Refusal> {
    match pair::load(label) {
        Ok(Some(pair)) => usable(pair, label),
        Ok(None) => Err(Refusal::config(format!(
            "no pair is stored under {label:?}; make one with `podssh relay pair {label}`"
        ))),
        Err(e) => Err(refusal(&e)),
    }
}

/// The operator's part of the pair stored under `label`, unless it has
/// expired, or the part that a pairing by code kept under it (T-086).
pub(crate) fn stored_part(label: &str) -> Result<pair::OperatorPart, Refusal> {
    match pair::load(label) {
        Ok(Some(found)) => usable(found, label).map(|kept| pair::OperatorPart::of(&kept)),
        Ok(None) => operator_part(label, None),
        Err(e) => Err(refusal(&e)),
    }
}

/// A pair from a file of the store's form, as `--pair-file` gives it.
pub(crate) fn from_file(path: &str) -> Result<Pair, Refusal> {
    pair::read_file(Path::new(path))
        .map_err(|e| Refusal::config(format!("--pair-file {path}: {}", podssh_ws::text::said(&e))))
}

/// `pair`, unless it has expired: then the remedy, with the code of an
/// expired pair (77).
pub(crate) fn usable(pair: Pair, label: &str) -> Result<Pair, Refusal> {
    if pair.expires_ms <= now_ms() {
        return Err(Refusal {
            message: format!(
                "the pair under {label:?} expired at {}; make a new one with `podssh relay pair {label}`",
                utc(pair.expires_ms)
            ),
            code: Fault::PairExpired.code(),
        });
    }
    Ok(pair)
}

/// The exit code and the message of a pairing call that failed. A `403` of
/// a pair's token is said in podssh's words (T-939): the crate's names a
/// stopped or expired pair alone, and a token of `--once` that took its one
/// upgrade gets the same `403`.
pub(crate) fn refusal(e: &PairError) -> Refusal {
    let code = match e {
        PairError::BadLabel(_) => Fault::Usage.code(),
        PairError::Forbidden => Fault::Auth.code(),
        PairError::Store(_) => Fault::Config.code(),
        PairError::Connect(c) => connect_code(c),
        _ => Fault::RelayUnreachable.code(),
    };
    let message = match e {
        PairError::Forbidden => format!("the relay refused the pair's token (403): {TOKEN_ENDED}"),
        PairError::BadLabel(_) => label_words(&e.to_string()),
        other => other.to_string(),
    };
    Refusal { message, code }
}

/// Why a relay refuses a pair's token: each of these gets the same `403`.
pub(crate) const TOKEN_ENDED: &str =
    "the pair was stopped or has expired, or it was made with --once and its connect token took its one upgrade";

/// A request for a new pair that failed: a `403` there names no pair, as
/// none was made (T-939). The relay that mints for a list of keys refuses a
/// key not on it; the crate keeps none of its words, so the line names this
/// client's key, which the owner adds.
pub(crate) fn made_refusal(e: &PairError) -> Refusal {
    let PairError::Forbidden = e else { return refusal(e) };
    let key = podssh_relay::identity::file::existing(&podssh_relay::identity::file::client_place())
        .ok()
        .flatten()
        .map(|identity| format!("; this client's key is {}", identity.public().fingerprint()))
        .unwrap_or_default();
    Refusal {
        message: format!(
            "the relay refused to make a pair (403): a relay of --mint keys:FILE or net makes pairs for the keys of \
             its list alone{key} (podssh keygen -y prints its line for that list)"
        ),
        code: Fault::Auth.code(),
    }
}

/// A connection that failed, as `podssh proxy` reads it: a setting (78), a
/// refusal (77), else no relay (69). A relay that reads another dialect of
/// the reverse road (426, T-643) is 78, as for a node: a retry repeats it.
fn connect_code(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => Fault::Config.code(),
        ConnectError::Refused { status: 426, .. } => Fault::Config.code(),
        ConnectError::Refused { status: 401 | 403, .. }
        | ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => Fault::Auth.code(),
        _ => Fault::RelayUnreachable.code(),
    }
}

/// `--ca-file`, else `SSL_CERT_FILE`, else podssh's own roots, as for
/// `podssh proxy`.
pub(crate) fn trust(ca_file: Option<&str>) -> Trust {
    let file = crate::settings::ca_file(ca_file);
    match file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    }
}

/// How a pairing call reaches `relay`.
pub(crate) fn context<'a>(relay: &'a Relay, trust: &'a Trust, context: &'a Context) -> PairContext<'a> {
    PairContext { relay, trust, ctx: context, timeout: REQUEST_LIMIT }
}

/// A refusal before any request when `PODSSH_OFFLINE` is set.
pub(crate) fn online() -> Result<(), Refusal> {
    if podssh_relay::open::offline() {
        return Err(Refusal {
            message: "not attempted: PODSSH_OFFLINE is set".into(),
            code: Fault::RelayUnreachable.code(),
        });
    }
    Ok(())
}

/// The operator's part for `label`: from `--pair-file` (a pair, or its
/// operator's part), else from the pair stored under `label`, else from the
/// operator's part that a pairing by code kept under it (T-086). Refused
/// when it has expired; past the end that it names, its relay is asked
/// first, as the pair's owner may have renewed it there (T-592).
pub(crate) fn operator_part(label: &str, pair_file: Option<&str>) -> Result<pair::OperatorPart, Refusal> {
    let part = match pair_file {
        Some(path) => pair::read_operator_file(Path::new(path))
            .map_err(|e| Refusal::config(format!("--pair-file {path}: {}", podssh_ws::text::said(&e))))?,
        None => match pair::load(label) {
            Ok(Some(found)) => pair::OperatorPart::of(&found),
            Ok(None) => match pair::part::load(label) {
                Ok(Some(part)) => part,
                Ok(None) => {
                    return Err(Refusal::config(format!(
                        "no pair is stored under {label:?}; make one with `podssh relay pair {label}`, take its \
                         part with `podssh relay join {label}` and the code that its node's host shows, or give \
                         its operator's file with --pair-file FILE"
                    )))
                }
                Err(e) => return Err(refusal(&e)),
            },
            Err(e) => return Err(refusal(&e)),
        },
    };
    if part.expires_ms <= now_ms() {
        return renewed(part, label);
    }
    Ok(part)
}

/// A part past the end that its file names: podssh's relay role may have
/// renewed the pair, whose tokens stay (T-592), so its relay's status is
/// asked once, and the later end that it names is taken. Offline, or where
/// the relay refuses the token or names no later end (a relay of the
/// contract names none), the refusal of an expired pair (77), as before.
fn renewed(mut part: pair::OperatorPart, label: &str) -> Result<pair::OperatorPart, Refusal> {
    let named = utc(part.expires_ms);
    let expired = |also: String| Refusal {
        message: format!(
            "the pair under {label:?} expired at {named}{also}; make a new one with `podssh relay pair {label}`"
        ),
        code: Fault::PairExpired.code(),
    };
    if podssh_relay::open::offline() {
        return Err(expired(String::new()));
    }
    match ended_at(&part) {
        Ok(Some(expires)) if expires > now_ms() => {
            part.expires_ms = expires;
            Ok(part)
        }
        Ok(_) | Err(PairError::Forbidden) => Err(expired(String::new())),
        Err(e) => Err(expired(format!(
            ", by its file, and its relay could not say whether it was renewed: {}",
            podssh_ws::text::said(&e)
        ))),
    }
}

/// The end that the relay names in its status of `part`, asked in a thread
/// of its own with the trust of `SSL_CERT_FILE` or the settings, as a caller
/// may run inside a runtime.
fn ended_at(part: &pair::OperatorPart) -> Result<Option<i64>, PairError> {
    std::thread::scope(|scope| {
        let asking = scope.spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| {
                PairError::Store(format!("could not start the async runtime: {}", podssh_ws::text::said(&e)))
            })?;
            let (trust, relay_ctx) = (trust(None), podssh_relay::context::process());
            let ctx = context(&part.relay, &trust, &relay_ctx);
            runtime.block_on(pair::renew::status(&ctx, part)).map(|status| status.expires)
        });
        asking.join().unwrap_or_else(|_| Err(PairError::Store("the status's thread ended in a panic".into())))
    })
}

/// How a session of the reverse road ended after `ready`, in words, the same
/// for `podssh operator` and `podssh ssh node://NAME`. With no Close (`1006`)
/// the link broke, and the relay drops links at random (T-255); a node that
/// lost its link connects again; `1012` is a relay that restarts, as podssh's
/// relay role closes each socket before a planned stop, and its node comes
/// back once the relay does. In each case a new session may work.
pub(crate) fn session_end(code: u16, reason: &str) -> String {
    match code {
        1006 => format!("the link to the relay ended with no Close ({reason}); a new session may work"),
        1011 if reason.trim().eq_ignore_ascii_case("node disconnected") => {
            "the node's link to the relay ended (relay close 1011: node disconnected); the node connects again, \
             so a new session may work"
                .to_string()
        }
        1012 => format!(
            "the relay is restarting (relay close 1012: {reason}); the node connects again once it is back, so a \
             new session may work"
        ),
        _ => format!("the relay ended the session (relay close {code}): {reason}"),
    }
}

/// A connection to the relay that failed for a pair: its code, and for a
/// refused token the remedy.
pub(crate) fn connect_refusal(e: &ConnectError, label: &str) -> Refusal {
    let message = match e {
        // The way's refusal of the upgrade, not the relay's (T-821, found
        // behind pod-lab's ws-upgrade-refused): said as it is.
        // A 426 is the relay's own of a dialect (T-643), never the way's here.
        ConnectError::Refused { status, body } if *status != 426 && podssh_relay::piping::probe::upgrade_refused(e) => {
            format!(
                "the way to the relay refused the WebSocket upgrade (HTTP {status}: {}), before the relay saw the pair",
                podssh_ws::text::one_line(body)
            )
        }
        // The relay's own words, when it gave more than the contract's.
        ConnectError::Refused { status: 403, body } => {
            let said = podssh_ws::text::one_line(body);
            let said = if said.is_empty() { String::new() } else { format!(": {said}") };
            format!(
                "the relay refused the pair (403{said}): {TOKEN_ENDED}; make a new one with `podssh relay pair {label}`"
            )
        }
        other => other.to_string(),
    };
    Refusal { message, code: connect_code(e) }
}

#[cfg(test)]
mod tests {
    use super::session_end;

    /// The way's 403 of the upgrade is said as the way's; the relay's own
    /// 403 of a pair as the pair's (T-821).
    #[test]
    fn a_way_s_refusal_of_the_upgrade_is_not_the_pair_s() {
        use podssh_ws::ConnectError;
        let way = ConnectError::Refused { status: 403, body: "Forbidden".into() };
        let said = super::connect_refusal(&way, "lab").message;
        assert!(said.contains("the way to the relay refused the WebSocket upgrade"), "{said}");
        let relay = ConnectError::Refused { status: 403, body: "reverse: forbidden".into() };
        let said = super::connect_refusal(&relay, "lab").message;
        assert!(said.starts_with("the relay refused the pair (403: reverse: forbidden)"), "{said}");
        assert!(said.contains("its connect token took its one upgrade"), "a spent token of --once is named: {said}");
    }

    /// A label that is no name is said with "the label" once (T-949), and
    /// stays a usage error.
    #[test]
    fn a_bad_label_is_said_once() {
        for (label, said) in [
            ("", "the label is empty"),
            (&"a".repeat(129)[..], "the label is longer than 128 characters"),
            ("-x", "the label \"-x\" is not a pair name"),
        ] {
            let refused = super::check_label(label).unwrap_err();
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{label}");
            assert_eq!(refused.message, said, "{label}");
        }
    }

    /// A refused request for a new pair names no pair; a refused token of a
    /// pair names each cause of its 403, the token of --once among them (T-939).
    #[test]
    fn a_refused_new_pair_is_not_a_stopped_one() {
        use podssh_relay::pair::PairError;
        let made = super::made_refusal(&PairError::Forbidden);
        assert_eq!(made.code, 77);
        assert!(made.message.starts_with("the relay refused to make a pair (403)"), "{}", made.message);
        assert!(!made.message.contains("expired"), "{}", made.message);
        let token = super::refusal(&PairError::Forbidden);
        assert_eq!(token.code, 77);
        assert!(token.message.contains("--once"), "{}", token.message);
    }

    #[test]
    fn a_session_that_ends_with_no_close_is_the_link_and_may_work_again() {
        let text = session_end(1006, "the relay closed the connection without a WebSocket Close");
        assert!(text.starts_with("the link to the relay ended with no Close ("), "{text}");
        assert!(text.ends_with("; a new session may work"), "{text}");
        assert!(!text.contains("relay close 1006"), "no Close came, so none is named: {text}");
    }

    #[test]
    fn a_node_that_lost_its_link_is_named_and_may_work_again() {
        for reason in ["node disconnected", " Node Disconnected "] {
            let text = session_end(1011, reason);
            assert!(
                text.starts_with("the node's link to the relay ended (relay close 1011: node disconnected)"),
                "{text}"
            );
            assert!(text.ends_with("so a new session may work"), "{text}");
        }
    }

    #[test]
    fn a_relay_that_restarts_is_named_and_may_work_again() {
        let text = session_end(1012, "relay restarting");
        assert!(text.starts_with("the relay is restarting (relay close 1012: relay restarting)"), "{text}");
        assert!(text.ends_with("so a new session may work"), "{text}");
    }

    #[test]
    fn each_other_end_keeps_the_relays_code_and_reason() {
        assert_eq!(session_end(1011, "write failed"), "the relay ended the session (relay close 1011): write failed");
        assert_eq!(session_end(1013, "slow"), "the relay ended the session (relay close 1013): slow");
    }

    /// T-643: an operator whose dialect the relay does not read exits 78,
    /// as a node does, with the relay's sentence.
    #[test]
    fn a_dialect_that_the_relay_does_not_read_is_78_with_its_words() {
        let words = "reverse: the operator speaks the reverse road's dialect 2, and the relay reads dialect 1 alone: \
                     update the relay";
        let refused = podssh_ws::ConnectError::Refused { status: 426, body: words.into() };
        let refusal = super::connect_refusal(&refused, "lab");
        assert_eq!(refusal.code, 78);
        assert!(refusal.message.ends_with("update the relay"), "{}", refusal.message);
    }
}
