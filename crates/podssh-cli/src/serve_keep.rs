//! The kept shells of `podssh serve NAME` (T-159): `--keep-lease TIME`, how
//! long a shell that its client detached waits for a client, and the record
//! of their names beside the host key, read at the start so that serve says
//! which shells the last run's end took with it.
//!
//! Under `--stdio`, serve is one connection's process, which ends with it:
//! no shell outlives it, so no shell is kept there. Under `--listen`
//! (T-124), which keeps no record beside a node's name, none is kept either:
//! only NAME keeps shells, as this entry specified.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use podssh_ssh::server::Control;

use crate::relay_settings::Refusal;

/// The lease where `--keep-lease` gives none: a job left at the end of a
/// day is there the next morning.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest lease: 30 days.
pub const LONGEST_LEASE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The lease of `--keep-lease`'s value: 0 (no shell is kept), or a whole
/// number, then s, m, h or d (none is seconds), up to 30 days.
pub fn parse_lease(text: &str) -> Result<Duration, String> {
    let bad = || format!("--keep-lease {text:?}: 0, or a whole number, then s, m, h or d, as 90s, 30m, 8h or 2d");
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let scale: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(bad()),
    };
    let seconds = number.parse::<u64>().ok().and_then(|n| n.checked_mul(scale)).ok_or_else(bad)?;
    let lease = Duration::from_secs(seconds);
    if lease > LONGEST_LEASE {
        return Err(format!("--keep-lease {text:?}: 30 days at most"));
    }
    Ok(lease)
}

/// The lease of the command line: `--keep-lease`'s, else
/// [`DEFAULT_LEASE`] under NAME; none under `--stdio` or `--listen`, where a
/// lease given is a usage error (64).
pub fn lease(given: Option<&str>, named: bool) -> Result<Duration, Refusal> {
    match (given, named) {
        (Some(_), false) => {
            Err(Refusal::usage("--keep-lease needs NAME: under --stdio or --listen, serve keeps no shell".to_string()))
        }
        (None, false) => Ok(Duration::ZERO),
        (Some(text), true) => parse_lease(text).map_err(Refusal::usage),
        (None, true) => Ok(DEFAULT_LEASE),
    }
}

/// The record's file name for the node NAME.
pub fn record_name(name: &str) -> String {
    format!("serve-{name}.kept")
}

/// Keep the names of the kept shells beside the host key at `host_key`,
/// and say which shells of the last run ended with it. A record that
/// cannot be read is said, and serve goes on with none.
pub fn at_start(control: &Control, host_key: &Path, name: &str, err: &mut dyn Write) {
    let Some(dir) = host_key.parent() else { return };
    let path = dir.join(record_name(name));
    match control.keep_record(path.clone()) {
        Ok(lost) if lost.is_empty() => {}
        Ok(lost) => {
            let _ = writeln!(
                err,
                "podssh serve: the last run kept {} shell(s), which ended with it: {}",
                lost.len(),
                lost.join(", ")
            );
        }
        Err(why) => {
            let _ = writeln!(err, "podssh serve: the record of the kept shells: {why}; none is written");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each form of a lease, one rule: a number and a unit, 30 days at most.
    #[test]
    fn a_lease_is_a_number_and_a_unit() {
        let cases: &[(&str, Option<u64>)] = &[
            ("0", Some(0)),
            ("90", Some(90)),
            ("90s", Some(90)),
            ("30m", Some(1800)),
            ("8h", Some(28_800)),
            ("2d", Some(172_800)),
            ("30d", Some(2_592_000)),
            ("31d", None),
            ("", None),
            ("h", None),
            ("1w", None),
            ("-1", None),
            ("99999999999999999999d", None),
        ];
        for (text, want) in cases {
            assert_eq!(parse_lease(text).ok().map(|d| d.as_secs()), *want, "{text:?}");
        }
    }

    /// No lease but under NAME (not --stdio, not --listen), and a given
    /// one is refused there.
    #[test]
    fn only_name_keeps_a_shell() {
        assert_eq!(lease(None, false).ok(), Some(Duration::ZERO));
        assert_eq!(lease(Some("1h"), false).map_err(|r| r.code).err(), Some(crate::exit_codes::EXIT_USAGE));
        assert_eq!(lease(None, true).ok(), Some(DEFAULT_LEASE));
        assert_eq!(lease(Some("0"), true).ok(), Some(Duration::ZERO));
    }
}
