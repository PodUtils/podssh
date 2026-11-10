//! What a Close carries, and what the relay's Close of a forward session
//! means: `pod-ws` of PodUtils/podcrates. What may help after one names
//! podssh's flags and commands, so it stays here ([`Remedy`]).

pub use pod_ws::close::*;

/// What may help after a Close of the forward path.
pub trait Remedy {
    /// What may help, when something may. The limits are the relay's
    /// (`/relays.json`, measured 2026-10-08): 180 s idle, 64 MiB, 12 h.
    fn remedy(self, reason: &str) -> Option<&'static str>;
}

impl Remedy for ForwardClose {
    fn remedy(self, reason: &str) -> Option<&'static str> {
        match self {
            ForwardClose::Target => Some("another relay host may reach it: --relay-host HOST"),
            // The link held; what crossed it came too slowly for the relay.
            ForwardClose::Client if reason.starts_with("client receive backlog") => Some(
                "the relay closes a session when 2 MiB wait for podssh: the link to the relay, or the reader of \
                 podssh's output, is slower than the target",
            ),
            ForwardClose::Client => Some("podssh doctor checks the way to the relay"),
            ForwardClose::Limit if reason.contains("idle") => {
                Some("the relay closes a session after 180 s with no traffic; set ServerAliveInterval below 180")
            }
            ForwardClose::Limit if reason.contains("byte cap") => {
                Some("a session carries 64 MiB at most through the relay; use a new session for more")
            }
            ForwardClose::Limit if reason.contains("time cap") => {
                Some("a session lasts 12 h at most through the relay; connect again")
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
        assert!(ForwardClose::Unknown.remedy("x").is_none());
        assert!(ForwardClose::Client.remedy("client receive backlog").unwrap().contains("2 MiB wait for podssh"));
        assert!(ForwardClose::Client.remedy("client send failed: reset").unwrap().contains("doctor"));
        assert_eq!(
            ForwardClose::Target.what("railway.new:22", "podssh"),
            "the relay lost its connection to railway.new:22"
        );
    }
}
