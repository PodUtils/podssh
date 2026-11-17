//! Whether a road of the resumable layer said why its session ended, so
//! that the SSH client does not say the same cause again in its own words
//! ("the connection closed unexpectedly"): one line for one cause (T-809).

use std::sync::atomic::{AtomicBool, Ordering};

use podssh_relay::session::client::Outcome;
use podssh_relay::session::End;

static TOLD: AtomicBool = AtomicBool::new(false);

/// A road said why its session ended.
pub(crate) fn told() {
    TOLD.store(true, Ordering::SeqCst);
}

/// Whether a road said it since the last call, which clears it.
pub(crate) fn take() -> bool {
    TOLD.swap(false, Ordering::SeqCst)
}

/// What the layer says of a session that did not end well: `None` for a
/// good end, and for a lost link, of which the road says more.
pub(crate) fn why_ended(outcome: Outcome) -> Option<String> {
    let why = ended_words(outcome);
    if why.is_some() {
        told();
    }
    why
}

fn ended_words(outcome: Outcome) -> Option<String> {
    match outcome {
        Outcome::Plain(_) => None,
        Outcome::Layer(ended) => match ended.end {
            End::Closed(reason) if !reason.is_empty() => {
                Some(format!("the far end ended the session: {}", podssh_ws::text::one_line(&reason)))
            }
            End::Broken(e) => Some(e.to_string()),
            End::GaveUp(gave) => {
                Some(format!("the session could not go on: {}", podssh_ws::text::one_line(&gave.reason)))
            }
            // The leg's close code and reason say more of a lost link.
            End::Closed(_)
            | End::LocalEnd
            | End::Closing
            | End::Lost(_)
            | End::Stopped
            | End::Retired
            | End::Moving => None,
        },
    }
}

/// The SSH client's words of a connection that the far end closed, as each
/// system says them: an end of the stream, a broken pipe (macOS), a reset.
const CLOSED: &[&str] = &["the connection closed unexpectedly", "broken pipe", "connection reset by peer"];

/// The lines of a failed run, less the SSH client's own words of a closed
/// connection when a road of the layer said the cause already.
fn lines(lines: Vec<String>, said: bool) -> Vec<String> {
    let echo = |line: &String| {
        let words = line.rsplit_once(": ").map_or(line.as_str(), |(_, words)| words).to_ascii_lowercase();
        CLOSED.iter().any(|closed| words.starts_with(closed))
    };
    if said && !lines.is_empty() && lines.iter().all(echo) {
        return Vec::new();
    }
    lines
}

/// After a run on a road of the layer, and its last line: its lines less
/// the client's echo of a cause that the road said.
pub(crate) fn once(run: &mut Vec<String>, layered: bool) {
    let said = take() && layered;
    *run = lines(std::mem::take(run), said);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_s_closed_line_goes_only_after_a_road_s_cause() {
        let closed = vec!["127.0.0.1:2299: the connection closed unexpectedly".to_string()];
        assert!(lines(closed.clone(), true).is_empty());
        assert_eq!(lines(closed.clone(), false), closed, "no cause said: the client's line stays");
        let piped = vec!["127.0.0.1:53370: broken pipe".to_string()];
        assert!(lines(piped, true).is_empty(), "macOS's words of the same end");
        let other = vec!["127.0.0.1:2299: the server did not answer with an SSH version line".to_string()];
        assert_eq!(lines(other.clone(), true), other, "another cause stays");
    }
}
