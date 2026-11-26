//! The flag rows of `ssh` for the frames of the far end's screen (T-303), in a
//! file of its own so that `flags.rs` stays under 500 lines. `SSH_FLAGS` names
//! them in their place, and `EACH_FLAGS` names the refusals of `each`.

use super::{row, FlagKind, FlagRow};

/// `--frames`: the far end's screen as its difference, at most each half
/// round trip, in place of each byte of the pty (`podssh_ssh::frames`).
#[rustfmt::skip]
pub const FRAMES: FlagRow = row(None, "frames", None, FlagKind::Supported,
    "show the far end's latest screen as frames, not each byte, so a flood does not hold back what follows Ctrl-C; only to podssh serve with a pty, also through a podssh control master; the terminal's scrollback gets nothing", None);

/// `--frames-scroll`: `--frames`, whose frames also carry the lines that
/// leave the top of the far end's screen, for the terminal's scrollback.
#[rustfmt::skip]
pub const FRAMES_SCROLL: FlagRow = row(None, "frames-scroll", None, FlagKind::Supported,
    "--frames, and the lines that leave the top of the far end's screen go into the terminal's scrollback, one screen for each frame at most", None);

/// `each --frames`: refused by name (64), not unknown. A frame draws one
/// terminal's screen, and `each` writes many hosts' output as lines with a
/// label and no pty, so there is no screen to draw.
#[rustfmt::skip]
pub const EACH_FRAMES: FlagRow = row(None, "frames", None, FlagKind::Refused,
    "frames draw one terminal's screen, and each writes each host's output as lines, with no pseudo-terminal", Some("podssh ssh --frames HOST"));

/// `each --frames-scroll`: refused as `--frames` is.
#[rustfmt::skip]
pub const EACH_FRAMES_SCROLL: FlagRow = row(None, "frames-scroll", None, FlagKind::Refused,
    "frames draw one terminal's screen, and each writes each host's output as lines, with no pseudo-terminal", Some("podssh ssh --frames-scroll HOST"));
