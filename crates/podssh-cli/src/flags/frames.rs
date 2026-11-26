//! The flag row of `ssh` for the frames of the far end's screen (T-303), in a
//! file of its own so that `flags.rs` stays under 500 lines. `SSH_FLAGS` names
//! it in its place.

use super::{row, FlagKind, FlagRow};

/// `--frames`: the far end's screen as its difference, at most each half
/// round trip, in place of each byte of the pty (`podssh_ssh::frames`).
#[rustfmt::skip]
pub const FRAMES: FlagRow = row(None, "frames", None, FlagKind::Supported,
    "show the far end's latest screen as frames, not each byte, so a flood does not hold back what follows Ctrl-C; only to podssh serve with a pty; the terminal's scrollback gets nothing", None);
