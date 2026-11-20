//! The pager of `podssh man`: `pod_manual::pager` of PodUtils/podcrates,
//! which was taken from this module (the owner's ruling "Shared code",
//! T-820). The crate's own tests hold it. What stays here is `show` under
//! its old words for `podssh man`; `Interrupts` (SIGINT and SIGQUIT held
//! while a pager or the editor of `podssh edit` runs) is the crate's.

pub use pod_manual::pager::{
    choose, find_program, page, read_key, run_program, Choice, Interrupts, Key, PagerEnv, Tty, PAGE_LINES,
};
use std::io::{BufRead, Write};

/// `text` through the pager that `env` chooses, as the crate's `show_with`.
pub fn show(text: &str, env: &PagerEnv, keys: &mut dyn BufRead, out: &mut dyn Write, err: &mut dyn Write) {
    pod_manual::pager::show_with(text, env, keys, out, err);
}
