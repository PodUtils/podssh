//! What a Close carries, and what the relay's Close of a forward session
//! means: `pod-ws` of PodUtils/podcrates. What may help after one names
//! podssh's flags and commands, so it stays here ([`Remedy`]).

pub use pod_ws::close::*;

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};

/// The idle limit of the relay that this run's sessions use, in ms, as its
/// `/relays.json` gave it; 0 where none was read (T-814).
static IDLE_MS: AtomicU64 = AtomicU64::new(0);

/// Keep the idle limit of the relay in use, for the words of its idle cut.
pub fn relay_idle_ms(ms: Option<u64>) {
    IDLE_MS.store(ms.unwrap_or(0), Ordering::Relaxed);
}

/// The words of an idle cut: the relay's own limit where it is known, as a
/// relay of the user's own can set any (`relay serve --idle`).
fn idle_words() -> Cow<'static, str> {
    match IDLE_MS.load(Ordering::Relaxed) / 1000 {
        0 => Cow::Borrowed(
            "the relay closes a session after its idle limit with no traffic (180 s at podssh's default relay); set \
             ServerAliveInterval below it",
        ),
        secs => Cow::Owned(format!(
            "the relay closes a session after {secs} s with no traffic; set ServerAliveInterval below {secs}"
        )),
    }
}

/// What may help after a Close of the forward path.
pub trait Remedy {
    /// What may help, when something may. The limits are the relay's
    /// (`/relays.json`, measured 2026-10-08): 180 s idle, 64 MiB, 12 h; the
    /// idle limit of the relay in use where it was read.
    fn remedy(self, reason: &str) -> Option<Cow<'static, str>>;
}

impl Remedy for ForwardClose {
    fn remedy(self, reason: &str) -> Option<Cow<'static, str>> {
        let fixed = |words: &'static str| Some(Cow::Borrowed(words));
        match self {
            ForwardClose::Target => fixed("another relay host may reach it: --relay-host HOST"),
            // The link held; what crossed it came too slowly for the relay.
            ForwardClose::Client if reason.starts_with("client receive backlog") => fixed(
                "the relay closes a session when 2 MiB wait for podssh: the link to the relay, or the reader of \
                 podssh's output, is slower than the target",
            ),
            ForwardClose::Client => fixed("podssh doctor checks the way to the relay"),
            ForwardClose::Limit if reason.contains("idle") => Some(idle_words()),
            ForwardClose::Limit if reason.contains("byte cap") => {
                fixed("a session carries 64 MiB at most through the relay; use a new session for more")
            }
            ForwardClose::Limit if reason.contains("time cap") => {
                fixed("a session lasts 12 h at most through the relay; connect again")
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod forward_close_tests {
    use super::*;

    /// The remedies of the relay's table, in podssh's words.
    #[test]
    fn forward_close_names_the_hop_for_each_row() {
        assert!(ForwardClose::Limit.remedy("idle timeout").unwrap().contains("ServerAliveInterval"));
        // The relay's own idle limit, where its /relays.json gave it (T-814).
        relay_idle_ms(Some(3000));
        assert!(ForwardClose::Limit.remedy("idle timeout").unwrap().contains("after 3 s with no traffic"));
        relay_idle_ms(None);
        assert!(ForwardClose::Limit.remedy("idle timeout").unwrap().contains("after its idle limit"));
        assert!(ForwardClose::Unknown.remedy("x").is_none());
        assert!(ForwardClose::Client.remedy("client receive backlog").unwrap().contains("2 MiB wait for podssh"));
        assert!(ForwardClose::Client.remedy("client send failed: reset").unwrap().contains("doctor"));
        assert_eq!(
            ForwardClose::Target.what("railway.new:22", "podssh"),
            "the relay lost its connection to railway.new:22"
        );
    }
}
