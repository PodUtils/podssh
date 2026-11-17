//! The pager of `podssh man`: `pod_manual::pager` of PodUtils/podcrates,
//! which was taken from this module (the owner's ruling "Shared code",
//! T-820). The crate's own tests hold it. What stays here is `show` under
//! its old words for `podssh man`, and `Interrupts`, which the editor of
//! `podssh edit` takes too and the crate keeps private: asked of podcrates
//! (COORD-115).

pub use pod_manual::pager::{
    choose, find_program, page, read_key, run_program, Choice, Key, PagerEnv, Tty, PAGE_LINES,
};
use std::io::{BufRead, Write};

/// `text` through the pager that `env` chooses, as the crate's `show_with`.
pub fn show(text: &str, env: &PagerEnv, keys: &mut dyn BufRead, out: &mut dyn Write, err: &mut dyn Write) {
    pod_manual::pager::show_with(text, env, keys, out, err);
}

/// SIGINT and SIGQUIT ignored while the value lives, then restored: while a
/// pager or the editor of `podssh edit` runs, the keys are the child's. The
/// whole action is kept and put back, its flags too, so a handler that tokio
/// installed before (`podssh edit` waits for SIGINT while a file moves)
/// stays as it was.
pub(crate) struct Interrupts {
    #[cfg(unix)]
    previous: [libc::sigaction; 2],
}

impl Interrupts {
    pub(crate) fn ignore() -> Interrupts {
        #[cfg(unix)]
        {
            // SAFETY: an all-zero sigaction is a valid value of the C type;
            // SIG_IGN with an empty mask has no preconditions, and Drop puts
            // back each action that was there.
            unsafe {
                let mut ignore: libc::sigaction = std::mem::zeroed();
                ignore.sa_sigaction = libc::SIG_IGN;
                libc::sigemptyset(&mut ignore.sa_mask);
                let mut previous: [libc::sigaction; 2] = std::mem::zeroed();
                libc::sigaction(libc::SIGINT, &ignore, &mut previous[0]);
                libc::sigaction(libc::SIGQUIT, &ignore, &mut previous[1]);
                Interrupts { previous }
            }
        }
        #[cfg(not(unix))]
        Interrupts {}
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: restores the actions that `ignore` read.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous[0], std::ptr::null_mut());
            libc::sigaction(libc::SIGQUIT, &self.previous[1], std::ptr::null_mut());
        }
    }
}
