//! The flag row of `ssh` for local echo (T-160), in a file of its own so that
//! `flags.rs` stays under 500 lines. `SSH_FLAGS` names it in its place.

use super::{row, FlagKind, FlagRow};

/// `--predict`: each typed key shows at once, underlined, where a far end
/// that reports its pty will echo it (`podssh_ssh::predict`).
#[rustfmt::skip]
pub const PREDICT: FlagRow = row(None, "predict", None, FlagKind::Supported,
    "show each typed key at once, underlined, before its echo; only to podssh serve with a pty, above a round trip of 120 ms", None);
