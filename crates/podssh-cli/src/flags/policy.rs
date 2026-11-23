//! The rows of `--policy FILE` (T-838): an algorithm policy that judges a
//! server's KEXINIT before any login. `ssh` goes on after a pass; `health`
//! gives the verdict alone, as a probe. A module of its own so that
//! `flags.rs` stays short; the rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// `ssh --policy FILE`.
#[rustfmt::skip]
pub const SSH_POLICY: FlagRow = row(None, "policy", Some("FILE"), FlagKind::Supported,
    "before the login, judge the server's KEXINIT by the algorithm policy in FILE; a mismatch exits 78 with the verdict as JSON on stdout", None);

/// `health --policy FILE`.
#[rustfmt::skip]
pub const HEALTH_POLICY: FlagRow = row(None, "policy", Some("FILE"), FlagKind::Supported,
    "in place of the facts, judge the server's KEXINIT by the algorithm policy in FILE, with no login: JSON on stdout; exit 0, 78 or 69", None);
