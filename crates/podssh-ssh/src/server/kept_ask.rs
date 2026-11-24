//! What a channel asks of the kept shells before its shell request, and
//! what the start of a login shell needs for it to be kept (T-159), apart
//! from `kept.rs` so that each file stays short.

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever kept there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::ffi::OsString;
use std::time::Duration;

use super::kept_shelf::Shelf;
use crate::keep::{check_name, ATTACH, COUNT, FROM, KEEP, LEASE, RESET, SHELL_ID, TAKE};

/// The longest lease that a client's `lease@podssh` may name: 30 days.
const LONGEST_ASK: u64 = 30 * 24 * 60 * 60;

/// What a channel asked of the kept shells before its shell request.
#[derive(Debug, Default, Clone)]
pub(super) struct Asked {
    /// `attach@podssh NAME`: the shell request joins NAME.
    pub(super) attach: Option<String>,
    /// `take@podssh yes`: from a client that has it.
    pub(super) take: bool,
    /// `from@podssh ID`: the shell that the client runs in.
    pub(super) from: Option<String>,
    /// `keep@podssh NAME`: keep the new shell as NAME if its client is lost.
    pub(super) keep: Option<String>,
    /// `lease@podssh SECONDS`: a shorter lease than serve's.
    pub(super) lease: Option<Duration>,
    /// `count@podssh OFFSET`: the shell's output that the client has (T-833).
    pub(super) count: Option<u64>,
    /// `reset@podssh yes`: the last output from a clean boundary (T-833).
    pub(super) reset: bool,
}

impl Asked {
    /// Note the `env` request `name`: `None` for a name that is not one of
    /// podssh's own (a client's variable), else whether its value is good.
    pub(super) fn note(&mut self, name: &str, value: &str) -> Option<bool> {
        let named = check_name(value).is_ok();
        let good = match name {
            ATTACH if named => {
                self.attach = Some(value.to_string());
                true
            }
            KEEP if named => {
                self.keep = Some(value.to_string());
                true
            }
            ATTACH | KEEP => false,
            // An id of a shell is 32 hexadecimal digits; a longer value
            // names no shell, and is refused.
            FROM if !value.is_empty() && value.len() <= 64 => {
                self.from = Some(value.to_string());
                true
            }
            FROM => false,
            TAKE => {
                self.take = value == "yes";
                true
            }
            RESET => {
                self.reset = value == "yes";
                true
            }
            COUNT => match value.parse::<u64>() {
                Ok(count) => {
                    self.count = Some(count);
                    true
                }
                Err(_) => false,
            },
            LEASE => match value.parse::<u64>() {
                Ok(seconds) if (1..=LONGEST_ASK).contains(&seconds) => {
                    self.lease = Some(Duration::from_secs(seconds));
                    true
                }
                _ => false,
            },
            _ => return None,
        };
        Some(good)
    }
}

/// What the start of a login shell needs for the shell to be kept.
pub(super) struct Keeper {
    pub(super) shelf: Shelf,
    /// The fingerprint of the key that logged in: the shell's owner.
    pub(super) owner: String,
    /// The lease: serve's, or the client's shorter one.
    pub(super) lease: Duration,
    /// serve's own lease, the longest.
    pub(super) cap: Duration,
    /// `keep@podssh NAME`.
    pub(super) keep: Option<String>,
}

impl Keeper {
    /// None where serve keeps no shells (a lease of 0), or with no key.
    pub(super) fn of(shelf: &Shelf, owner: &str, cap: Duration, asked: &Asked) -> Option<Keeper> {
        if cap.is_zero() || owner.is_empty() {
            return None;
        }
        let lease = asked.lease.map_or(cap, |lease| lease.min(cap));
        Some(Keeper { shelf: shelf.clone(), owner: owner.to_string(), lease, cap, keep: asked.keep.clone() })
    }
}

/// A new id of a shell that may be kept: 128 random bits in hex. None
/// where the system gives no random bytes: the shell is then never kept.
pub(super) fn new_id() -> Option<String> {
    use std::fmt::Write as _;
    let mut bits = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bits).ok()?;
    let mut id = String::with_capacity(32);
    for b in bits {
        let _ = write!(id, "{b:02x}");
    }
    Some(id)
}

/// `env` with the shell's id as `PODSSH_SHELL_ID`, in the place of any.
pub(super) fn with_id(mut env: Vec<(OsString, OsString)>, id: &str) -> Vec<(OsString, OsString)> {
    env.retain(|(name, _)| name != SHELL_ID);
    env.push((SHELL_ID.into(), id.into()));
    env
}
