//! The flag rows of `tx` (T-831): its subcommands `send FILE` and
//! `receive [DIR]` take a word each, and no flag.

use super::FlagRow;

/// **`tx`.** The far end of the 7-bit envelope, in the shell of a `podssh
/// ssh` session: a file through the terminal itself.
pub const TX_FLAGS: &[FlagRow] = &[];
