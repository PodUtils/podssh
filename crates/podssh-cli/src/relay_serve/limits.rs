//! The limits of `podssh relay serve` that its operator can move (T-704,
//! GitHub #169): `--keepalive`, `--idle`, `--session-hours`,
//! `--max-session-mib` and `--connect`. The defaults are the compiled caps
//! of the default relay (`Limits::default()`, the facts of `pod-services`).
//! A value above a default is allowed: it moves this role's cut only, and a
//! client keeps its own lower budgets, as it only ever lowers them to what
//! `/relays.json` publishes. The bounds are for the operator's sense, not a
//! client's safety.

use std::time::Duration;

use podssh_relay::serve::Limits;

use super::ServeArgs;
use crate::relay_settings::Refusal;

/// A whole number of `unit`s from `least` to `most`, or a usage refusal
/// that names the flag and the range.
fn whole(flag: &str, text: &str, least: u64, most: u64, unit: &str) -> Result<u64, Refusal> {
    match text.trim().parse::<u64>() {
        Ok(n) if (least..=most).contains(&n) => Ok(n),
        _ => Err(Refusal::usage(format!("{flag} {text:?}: {unit}, from {least} to {most}"))),
    }
}

/// `flag`'s value, made into the limit by `make`, else `default`.
fn pick<T>(
    flag: &str,
    text: Option<&str>,
    (least, most, unit): (u64, u64, &str),
    default: T,
    make: impl Fn(u64) -> T,
) -> Result<T, Refusal> {
    match text {
        None => Ok(default),
        Some(text) => whole(flag, text, least, most, unit).map(make),
    }
}

/// The limits that the flags of `s` give; each other one is the default's.
pub(super) fn of(s: &ServeArgs) -> Result<Limits, Refusal> {
    let d = Limits::default();
    Ok(Limits {
        keepalive: pick("--keepalive", s.keepalive.as_deref(), (1, 3600, "seconds"), d.keepalive, Duration::from_secs)?,
        idle: pick("--idle", s.idle.as_deref(), (1, 86_400, "seconds"), d.idle, Duration::from_secs)?,
        session: pick("--session-hours", s.session_hours.as_deref(), (1, 168, "hours"), d.session, |h| {
            Duration::from_secs(h * 3600)
        })?,
        bytes: pick("--max-session-mib", s.max_session_mib.as_deref(), (1, 4096, "MiB"), d.bytes, |m| m << 20)?,
        connect: pick("--connect", s.connect.as_deref(), (1, 120, "seconds"), d.connect, Duration::from_secs)?,
        ..d
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(f: impl FnOnce(&mut ServeArgs)) -> Result<Limits, Refusal> {
        let mut s = ServeArgs::default();
        f(&mut s);
        of(&s)
    }

    #[test]
    fn no_flag_is_the_compiled_default() {
        let d = Limits::default();
        let l = of(&ServeArgs::default()).unwrap();
        assert_eq!(
            (l.connect, l.idle, l.session, l.bytes, l.keepalive),
            (d.connect, d.idle, d.session, d.bytes, d.keepalive)
        );
    }

    #[test]
    fn each_flag_takes_its_unit() {
        let l = with(|s| {
            s.keepalive = Some("7".into());
            s.idle = Some("5".into());
            s.session_hours = Some("24".into());
            s.max_session_mib = Some("512".into());
            s.connect = Some("30".into());
        })
        .unwrap();
        assert_eq!(l.keepalive, Duration::from_secs(7));
        assert_eq!(l.idle, Duration::from_secs(5));
        assert_eq!(l.session, Duration::from_secs(24 * 3600));
        assert_eq!(l.bytes, 512 << 20);
        assert_eq!(l.connect, Duration::from_secs(30));
        // Above the compiled defaults is allowed (T-704).
        assert!(l.session > Limits::default().session && l.bytes > Limits::default().bytes);
    }

    /// A flag, how it is set, two values that it takes and two it refuses.
    type Case = (&'static str, fn(&mut ServeArgs, String), [&'static str; 2], [&'static str; 2]);

    #[test]
    fn each_flag_has_its_bounds_and_refuses_what_is_not_a_whole_number() {
        let set: [Case; 5] = [
            ("--keepalive", |s, v| s.keepalive = Some(v), ["1", "3600"], ["0", "3601"]),
            ("--idle", |s, v| s.idle = Some(v), ["1", "86400"], ["0", "86401"]),
            ("--session-hours", |s, v| s.session_hours = Some(v), ["1", "168"], ["0", "169"]),
            ("--max-session-mib", |s, v| s.max_session_mib = Some(v), ["1", "4096"], ["0", "4097"]),
            ("--connect", |s, v| s.connect = Some(v), ["1", "120"], ["0", "121"]),
        ];
        for (flag, put, good, bad) in set {
            for v in good {
                assert!(with(|s| put(s, v.into())).is_ok(), "{flag} {v}");
            }
            for v in bad.into_iter().chain(["-1", "1.5", "5s", "", "x"]) {
                let refused = with(|s| put(s, v.into())).unwrap_err();
                assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{flag} {v:?}");
                assert!(refused.message.starts_with(&format!("{flag} {v:?}: ")), "{refused}");
            }
        }
        let hours = with(|s| s.session_hours = Some("169".into())).unwrap_err();
        assert!(hours.message.contains("hours, from 1 to 168"), "{hours}");
    }
}
