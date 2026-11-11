//! The budget of a far end's replay buffers (T-586): `pod-session` of
//! PodUtils/podcrates, with the place of its lines. A process runs one
//! node, so one place: set by the node's command, and with none, a far end
//! says nothing (a test, a far end of `podssh serve`). Each keeper of
//! podssh takes [`told`].

use std::sync::{Arc, OnceLock};

pub use pod_session::budget::*;

/// What changes a node's budget, in podssh's words.
pub const CHANGE_WORDS: &str = "--resume-deadline and PODSSH_REPLAY_BUFFER of the node";

type Say = Box<dyn Fn(&str) + Send + Sync>;

static SAY: OnceLock<Say> = OnceLock::new();

/// Send the budget's lines to `say` from now on: a node's stderr, which a
/// detached node's log keeps. The first call holds.
pub fn tell(say: impl Fn(&str) + Send + Sync + 'static) {
    let _ = SAY.set(Box::new(say));
}

/// Say `line` where [`tell`] sends the budget's lines, if anywhere.
pub fn say(line: &str) {
    if let Some(say) = SAY.get() {
        say(line);
    }
}

/// The sink of a keeper's lines: where [`tell`] sends them, with podssh's
/// words of what changes the budget.
pub fn told() -> Tell {
    Tell::new(Arc::new(|event: pod_core::Event| say(&event.text)), CHANGE_WORDS)
}
