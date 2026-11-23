//! An algorithm policy (T-838): a named file of the algorithms that a peer
//! must offer, and a verdict on what it offered. The file is ssh-audit's
//! grammar ([`file`]); the verdict is a total, I/O-free function of the
//! policy and an observation ([`verdict::evaluate`]), so that the same check
//! judges a server's KEXINIT from `podssh ssh` and `podssh health`, and can
//! judge a client's for `podssh serve`. Its exit contract is sysexits: 0 pass, 78 a
//! mismatch, 69 no reading; ssh-audit's 3, 2 and 1 are not podssh's.
//!
//! What it fixes of ssh-audit: a host key's size is read on the type of the
//! key that actually came, and a key of another type than the one requested
//! is a mismatch, not a size of the requested type. A check that one
//! reading cannot make (a size of a type that the exchange did not agree)
//! is said as not measured, never passed.

pub mod file;
pub mod kexinit;
mod seen;
pub mod verdict;

use std::sync::{Arc, Mutex};

pub use file::{parse, Policy, PolicyError, SizeRule, MAX_BYTES};
pub use seen::observe;
pub use verdict::{evaluate, HostKeySeen, Mismatch, Observed, Side, Verdict};

/// The policy passed.
pub const EXIT_PASS: i32 = 0;
/// The peer offered what the policy does not allow, or the file cannot be
/// used: a fault of the setup (sysexits' EX_CONFIG).
pub const EXIT_MISMATCH: i32 = 78;
/// No verdict: no KEXINIT was read whole, or a check could not be made
/// (sysexits' EX_UNAVAILABLE).
pub const EXIT_NO_READING: i32 = 69;

/// What a handshake's record kept before the keys: each side's first
/// KEXINIT payload, the far end's version line and the line before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offers {
    pub theirs: Option<Vec<u8>>,
    pub ours: Option<Vec<u8>>,
    pub banner: Option<String>,
    pub header: Option<String>,
}

/// The reading of one handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// No handshake reached the host key yet.
    None,
    /// The handshake reached the host key, and what came does not read.
    Failed(String),
    Judged(Verdict),
}

/// A policy at work on one connection: the destination's handler judges
/// the server's KEXINIT at its host key, before any authentication, and
/// keeps the reading here for the command to report.
#[derive(Debug)]
pub struct Judge {
    policy: Policy,
    /// End each connection after the verdict, as a probe: `health --policy`
    /// needs no login.
    probe: bool,
    reading: Mutex<Reading>,
}

impl Judge {
    pub fn new(policy: Policy, probe: bool) -> Arc<Judge> {
        Arc::new(Judge { policy, probe, reading: Mutex::new(Reading::None) })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn reading(&self) -> Reading {
        self.reading.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Judge `observed`, or keep why there is nothing to judge; `Some` is
    /// why the connection ends here.
    pub fn judge(&self, observed: Result<Observed, String>) -> Option<String> {
        let reading = match observed {
            Ok(observed) => Reading::Judged(evaluate(&self.policy, &observed)),
            Err(why) => Reading::Failed(why),
        };
        let stop = match &reading {
            Reading::Judged(v) if v.passed() && !self.probe => None,
            Reading::Judged(v) if v.passed() => Some(format!("{}; a probe ends before the login", v.line())),
            Reading::Judged(v) => Some(format!("{}; refusing to log in", v.line())),
            Reading::Failed(why) => Some(format!("no verdict of the policy {:?}: {why}", self.policy.name)),
            Reading::None => None,
        };
        *self.reading.lock().unwrap_or_else(|e| e.into_inner()) = reading;
        stop
    }

    /// Whether the connection ended at this judge: a mismatch, no reading,
    /// or a probe.
    pub fn ended(&self) -> bool {
        match self.reading() {
            Reading::Judged(v) => self.probe || !v.passed(),
            Reading::Failed(_) => true,
            Reading::None => false,
        }
    }

    /// The reading as one JSON object, and its exit code; `why` says why
    /// there is none when no handshake reached the host key.
    pub fn report(&self, why: &str) -> (serde_json::Value, i32) {
        match self.reading() {
            Reading::Judged(v) => (v.json(), v.exit()),
            Reading::Failed(failed) => (self.no_reading(&failed), EXIT_NO_READING),
            Reading::None => (self.no_reading(why), EXIT_NO_READING),
        }
    }

    /// [`Judge::report`] as one line of stdout; its exit code. The verdict
    /// is the command's answer, as `--json` is another command's.
    pub fn print(&self, why: &str) -> i32 {
        use std::io::Write;
        let (doc, code) = self.report(why);
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{doc}");
        let _ = out.flush();
        code
    }

    fn no_reading(&self, why: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": 1, "policy": self.policy.name, "version": self.policy.version, "verdict": "no reading",
            "exit": EXIT_NO_READING, "mismatches": [], "unmeasured": [], "why": why,
        })
    }
}

#[cfg(test)]
mod file_tests;
#[cfg(test)]
mod tests;
