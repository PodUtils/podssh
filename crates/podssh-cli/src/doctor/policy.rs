//! `doctor --hop HOST --policy FILE` (T-838): the hop's algorithms judged by
//! an algorithm policy, with no login. One more connection runs the key
//! exchange to the host key, where the same judge as `ssh --policy` and
//! `health --policy` reads the server's KEXINIT (`podssh_ssh::probe::
//! algorithm_policy`); the connection ends there.
//!
//! The verdict is one doctor line, under doctor's own exit rule: a mismatch
//! is `FAIL` (exit 1), and no reading, or a check that one reading cannot
//! make, is `????`, which never fails the run. The JSON verdict and the
//! exits 78 and 69 are `health --policy`'s.

use podssh_ssh::policy::{Mismatch, Policy, Verdict as Judged, EXIT_MISMATCH, EXIT_PASS};
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::{Trust, Verdict};

use super::net::PROBE;

/// The label of the policy's line.
pub(super) const LABEL: &str = "hop policy";

/// The policy's line for the hop at `host`:`port`, on a connection of its own.
pub(super) async fn check(
    host: &str,
    port: u16,
    choice: &ProxyChoice,
    tls: Option<&Trust>,
    policy: &Policy,
) -> Verdict {
    let reading = match dial::dial(host, port, choice, PROBE).await {
        Err(e) => Err(format!("another connection failed: {e}")),
        Ok(stream) => match super::hop::wrapped(stream, host, tls).await {
            Err(why) => Err(format!("another connection's TLS: {why}")),
            // The handshake and the host key's signature, as `key` bounds them.
            Ok(stream) => podssh_ssh::probe::algorithm_policy(stream, policy, PROBE).await,
        },
    };
    line(reading, &policy.name)
}

/// The line of a reading: ok with the policy's name on a pass; a failure
/// that names each mismatch; a note when there is no reading, or when a
/// check could not be made.
pub(super) fn line(reading: Result<Judged, String>, name: &str) -> Verdict {
    match reading {
        Ok(v) if v.exit() == EXIT_PASS => Verdict::Ok {
            detail: format!("the server's algorithms meet the policy {:?} (version {})", v.policy, v.version),
        },
        Ok(v) if v.exit() == EXIT_MISMATCH => Verdict::Failed {
            detail: format!(
                "the server's algorithms do not meet the policy {:?}: {}",
                v.policy,
                v.mismatches.iter().map(mismatch).collect::<Vec<_>>().join("; ")
            ),
        },
        Ok(v) => Verdict::Unknown {
            why: format!(
                "the policy {:?} found no mismatch, and one reading cannot measure: {}",
                v.policy,
                v.unmeasured.join(", ")
            ),
        },
        Err(why) => Verdict::Unknown { why: format!("no reading for the policy {name:?}: {why}") },
    }
}

/// One mismatch: `FIELD: expected A,B, got C`, with the names that the
/// policy allows besides.
fn mismatch(m: &Mismatch) -> String {
    let names = |list: &[String]| if list.is_empty() { "nothing".to_string() } else { list.join(",") };
    let optional = if m.optional.is_empty() { String::new() } else { format!(" (optional {})", m.optional.join(",")) };
    format!("{}: expected {}{optional}, got {}", m.field, names(&m.expected), names(&m.actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(mismatches: Vec<Mismatch>, unmeasured: &[&str]) -> Judged {
        Judged {
            policy: "curve25519 only".into(),
            version: 2,
            mismatches,
            unmeasured: unmeasured.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// One table: each reading, its status and the words that its line
    /// must carry.
    #[test]
    fn the_line_names_the_policy_and_each_mismatch_and_notes_no_reading() {
        let kex = Mismatch {
            field: "key exchanges".into(),
            expected: names(&["curve25519-sha256"]),
            optional: vec![],
            actual: names(&["curve25519-sha256", "diffie-hellman-group14-sha256"]),
        };
        let macs = Mismatch {
            field: "MACs".into(),
            expected: names(&["hmac-sha2-256"]),
            optional: names(&["umac-128@openssh.com"]),
            actual: vec![],
        };
        type Case = (Result<Judged, String>, &'static str, &'static [&'static str]);
        let cases: Vec<Case> = vec![
            (Ok(verdict(vec![], &[])), "ok", &["meet the policy \"curve25519 only\" (version 2)"]),
            (
                Ok(verdict(vec![kex, macs], &[])),
                "fail",
                &[
                    "do not meet the policy \"curve25519 only\"",
                    "key exchanges: expected curve25519-sha256, got curve25519-sha256,diffie-hellman-group14-sha256",
                    "; MACs: expected hmac-sha2-256 (optional umac-128@openssh.com), got nothing",
                ],
            ),
            (
                Ok(verdict(vec![], &["host key size rsa-sha2-512"])),
                "unknown",
                &["found no mismatch", "cannot measure: host key size rsa-sha2-512"],
            ),
            (
                Err("no host key within 8 s".into()),
                "unknown",
                &["no reading for the policy \"curve25519 only\": no host key within 8 s"],
            ),
        ];
        for (reading, status, words) in cases {
            let (got, text) = match line(reading, "curve25519 only") {
                Verdict::Ok { detail } => ("ok", detail),
                Verdict::Failed { detail } => ("fail", detail),
                Verdict::Unknown { why } => ("unknown", why),
            };
            assert_eq!(got, status, "{text}");
            for word in words {
                assert!(text.contains(word), "{word:?} not in {text:?}");
            }
        }
    }
}
