//! File hosts as the last carrier of the resumable layer (T-738): for a
//! proxy that refuses each other road, each piece of a link is one upload
//! to a public file host that takes a file with no account on port 443 and
//! names its URL itself, and a meeting point ([`board::Board`]) carries that
//! URL, sealed, to the far end. The operator's ruling Q78 makes these hosts
//! the last of the last fallbacks, whatever their terms. Their names, forms
//! and limits are `pod-services`' (a kind `file-host`), never this crate's:
//! the code works over [`host::Host`] and [`form::Form`] alone.
//!
//! - Each piece is sealed under a key of the pair's secret before it leaves
//!   ([`keys`]), so a host holds ciphertext; its note on the board (the
//!   host, the URL, the delete token) is sealed too, as a board's topics are
//!   public. No host lets the uploader name a path, so the far end learns
//!   each URL from the board, not by derivation.
//! - The reader polls the board for piece N's topic, fetches the piece,
//!   opens it, deletes it where the host allows, and clears the topic
//!   ([`carrier`]).
//! - The bounds ([`pace`]): one outbound connection of the road at a time,
//!   an upload rate under each host's published one, pieces of at most
//!   [`PIECE_MOST`], a User-Agent that names podssh ([`USER_AGENT`]); a host
//!   that answers 429 rests, and the next host takes the piece.
//! - [`third_party_line`] is said before the first upload to each host.
//! - The hosts are `pod-services`' services of the kind `file-host`, read
//!   into forms ([`services`]) and reached over HTTPS ([`http`]); the board
//!   is a public MQTT broker of the kind `mqtt-broker` ([`mqtt`]); a node
//!   and a client run the layer over its links ([`road`]).
//!
//! The road is slow: an upload, a note, a poll and a download for each
//! piece, some seconds each way at best. It carries a command's output and
//! files, never a keystroke's echo in time. Above it run the resumable layer
//! and the end-to-end channel, as over each other road.

pub mod board;
pub mod carrier;
pub mod form;
pub mod host;
pub mod http;
pub mod keys;
pub mod link;
pub mod mqtt;
pub mod pace;
pub mod road;
pub mod services;

#[cfg(test)]
mod carrier_tests;
#[cfg(test)]
mod standin;

use std::sync::Arc;

pub use board::Board;
pub use carrier::Carrier;
pub use host::{Host, Refusal, Stored};
pub use keys::{Keys, LinkId, Way};
pub use link::Link;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The most bytes of one piece before its seal: a host's whole upload stays
/// small, and a piece that fails costs little to send again.
pub const PIECE_MOST: usize = 4 * 1024 * 1024;

/// What podssh says it is, in each request of the road: 0x0's notes for
/// client authors ask for a User-Agent that names the program and does not
/// pass for a browser, and an operator who sees it can find the project.
pub const USER_AGENT: &str =
    concat!("podssh/", env!("CARGO_PKG_VERSION"), " (file-host carrier; https://github.com/PodUtils/podssh)");

/// `no` turns the road off; a list of `pod-services` ids, by commas, keeps
/// only those hosts, in that order.
pub const ENV: &str = "PODSSH_FILEHOSTS";
/// `no` turns off each last fallback of Q78, this road among them.
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice<'a> {
    /// No road, and the variable (or `pod-services`) that left it off.
    Off(&'static str),
    /// These hosts, in order.
    On(Vec<&'a str>),
}

/// Whether a switch's value says no: unset, empty or yes is on; `None` for
/// another word.
fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// [`ENV`]'s `value` and [`LAST_RESORT`]'s `last` over the hosts that
/// `pod-services` lists (`listed`, by id, in their rank). A word of
/// [`LAST_RESORT`] that is neither yes nor no is no, as the switch of the
/// third parties fails closed. An id that `pod-services` does not list is
/// refused by name: an id is no secret, and a typo should not pass for a
/// choice.
pub fn choose<'a>(value: Option<&str>, last: Option<&str>, listed: &[&'a str]) -> Result<Choice<'a>, String> {
    choose_of(value, last, listed, listed)
}

/// [`choose`], where yes or unset takes `unasked` alone (the hosts whose
/// terms let a program upload with no word of its user), and a list may
/// name each host of `listed`: naming a host is the user's consent that its
/// operator asks for.
pub fn choose_of<'a>(
    value: Option<&str>,
    last: Option<&str>,
    listed: &[&'a str],
    unasked: &[&'a str],
) -> Result<Choice<'a>, String> {
    if says_no(value) == Some(true) {
        return Ok(Choice::Off(ENV));
    }
    if says_no(last) != Some(false) {
        return Ok(Choice::Off(LAST_RESORT));
    }
    let chosen: Vec<&'a str> = match says_no(value) {
        Some(_) => unasked.to_vec(),
        None => {
            let mut chosen = Vec::new();
            for id in value.unwrap_or_default().split(',').map(str::trim).filter(|id| !id.is_empty()) {
                let Some(known) = listed.iter().find(|known| known.eq_ignore_ascii_case(id)) else {
                    let shown = podssh_ws::text::one_line(&id.chars().take(40).collect::<String>());
                    return Err(format!("{ENV}: yes, no, or ids of file hosts that podssh lists; not {shown}"));
                };
                if !chosen.contains(known) {
                    chosen.push(*known);
                }
            }
            chosen
        }
    };
    if chosen.is_empty() {
        return Ok(Choice::Off("pod-services"));
    }
    Ok(Choice::On(chosen))
}

/// The line said before the first upload to `host` (Q78; 0x0's notes ask
/// that a user learns, in a way that cannot be missed, that the host is
/// public and run by one person): the host, that nobody vouches for it,
/// that the road is slow, and how to turn it off.
pub fn third_party_line(host: &str, one_person: bool) -> String {
    let run_by = if one_person { ", run by one person," } else { "" };
    format!(
        "the file-host road, the last of the last fallbacks: {host}, a public file host{run_by} that nobody \
         vouches for, keeps each piece of this session until it is read or its shortest life ends (the \
         operator's ruling Q78); each piece is sealed, and SSH and the end-to-end channel keep the bytes \
         private; the road is slow, for output and files, not for typing; {ENV}=no or {LAST_RESORT}=no turns \
         it off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTED: &[&str] = &["host-a", "host-b", "host-c"];

    #[test]
    fn the_switches_turn_the_road_off_keep_named_hosts_or_refuse_an_unknown_id() {
        assert_eq!(choose(None, None, LISTED), Ok(Choice::On(LISTED.to_vec())));
        assert_eq!(choose(Some("yes"), Some(""), LISTED), Ok(Choice::On(LISTED.to_vec())));
        for off in ["no", "OFF", " 0 ", "false"] {
            assert_eq!(choose(Some(off), None, LISTED), Ok(Choice::Off(ENV)), "{off}");
        }
        assert_eq!(choose(None, Some("no"), LISTED), Ok(Choice::Off(LAST_RESORT)));
        assert_eq!(choose(None, Some("maybe"), LISTED), Ok(Choice::Off(LAST_RESORT)), "fails closed");
        assert_eq!(choose(Some("host-c, HOST-A,host-c"), None, LISTED), Ok(Choice::On(vec!["host-c", "host-a"])));
        let refused = choose(Some("host-a,elsewhere"), None, LISTED).unwrap_err();
        assert!(refused.starts_with("PODSSH_FILEHOSTS: ") && refused.contains("elsewhere"), "{refused}");
        assert_eq!(choose(None, None, &[]), Ok(Choice::Off("pod-services")), "no host listed");
        assert_eq!(choose(Some(" , "), None, LISTED), Ok(Choice::Off("pod-services")), "an empty list");
    }

    #[test]
    fn a_host_that_is_not_taken_unasked_comes_only_when_named() {
        let unasked = &LISTED[..2];
        assert_eq!(choose_of(None, None, LISTED, unasked), Ok(Choice::On(unasked.to_vec())));
        assert_eq!(choose_of(Some("yes"), None, LISTED, unasked), Ok(Choice::On(unasked.to_vec())));
        assert_eq!(choose_of(Some("host-c"), None, LISTED, unasked), Ok(Choice::On(vec!["host-c"])), "named");
        assert_eq!(choose_of(None, None, LISTED, &[]), Ok(Choice::Off("pod-services")));
        assert_eq!(choose_of(Some("host-c"), Some("no"), LISTED, unasked), Ok(Choice::Off(LAST_RESORT)));
    }

    #[test]
    fn the_third_party_line_names_the_host_the_risk_the_speed_and_the_switches() {
        let line = third_party_line("files.stand-in.test", true);
        for words in [
            "files.stand-in.test",
            "run by one person",
            "nobody vouches for",
            "Q78",
            "sealed",
            "slow",
            "PODSSH_FILEHOSTS=no",
            "PODSSH_LAST_RESORT=no",
        ] {
            assert!(line.contains(words), "{words:?} in {line}");
        }
        assert!(!third_party_line("h.test", false).contains("one person"));
        assert!(USER_AGENT.starts_with("podssh/") && !USER_AGENT.contains("Mozilla"), "{USER_AGENT}");
    }
}
