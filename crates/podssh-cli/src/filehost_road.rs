//! `PODSSH_FILEHOSTS` (T-738): the file hosts' road of a pair, the last of
//! the last fallbacks of the operator's ruling Q78, in a build with the
//! feature `filehost`. Each piece of a link is one sealed upload to a public
//! file host of `pod-services` (its kind `file-host`), and its URL a sealed
//! note at a public MQTT broker (its kind `mqtt-broker`, T-737's). Unset,
//! empty or `yes` takes the hosts that the catalog ranks and whose terms let
//! a program upload unasked; a list of the catalog's ids takes those alone
//! (naming a host is the consent that its operator asks for); `no` turns the
//! road off, and so do `PODSSH_LAST_RESORT=no` and `PODSSH_MQTT=no` (no
//! board, no road). podssh names no host of its own.

use std::sync::Arc;

use podssh_relay::filehost::http::HttpHost;
use podssh_relay::filehost::mqtt::MqttBoard;
use podssh_relay::filehost::pace::Gate;
use podssh_relay::filehost::{self, Board, Carrier, Choice, Host, Keys, Say};
use podssh_ws::ProxyChoice;

use crate::relay_settings::Refusal;

/// The variable of the road.
pub const ENV: &str = filehost::ENV;
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = filehost::LAST_RESORT;

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that said so.
    Off(&'static str),
    /// The road through these hosts of the catalog, by id, in order.
    On(Vec<String>),
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// over the catalog's ids (`listed`) and those taken unasked. An id that the
/// catalog does not hold is a configuration error.
pub fn setting_of(
    value: Option<&str>,
    last: Option<&str>,
    listed: &[&str],
    unasked: &[&str],
) -> Result<Setting, String> {
    Ok(match filehost::choose_of(value, last, listed, unasked)? {
        Choice::Off(why) => Setting::Off(why),
        Choice::On(ids) => Setting::On(ids.into_iter().map(str::to_string).collect()),
    })
}

/// The setting of this process's variables; a bad one is refused (78)
/// before anything connects.
pub fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    let (listed, unasked) = filehost::services::ids();
    setting_of(value.as_deref(), last.as_deref(), &listed, &unasked).map_err(Refusal::config)
}

/// The hosts of the road, when it is on in this build; a bad setting reads
/// as off here, as [`setting`] refused it before the race.
pub fn on() -> Option<Vec<String>> {
    match setting() {
        Ok(Setting::On(ids)) if cfg!(feature = "filehost") => Some(ids),
        _ => None,
    }
}

/// The road of one pair: its carrier, and the names of its hosts and of
/// its board, for the lines.
pub struct Built {
    pub carrier: Arc<Carrier>,
    pub hosts: Vec<String>,
    pub board: String,
}

/// The road of the pair `name` with `token` over the hosts `ids`, with its
/// lines (each host's third party's line among them) to `say`; why none,
/// when no host's facts read or no broker is on.
pub fn built(ids: &[String], name: &str, token: &str, say: Say) -> Result<Built, String> {
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (forms, missed) = filehost::services::forms(&ids);
    for why in missed {
        say(format!("a file host left out: {why}"));
    }
    // The hosts and the broker are public: the host's own trust, never a
    // pair's CA file.
    let trust = crate::pairs::trust(None);
    let dial = podssh_relay::smee::http::tls(trust.clone(), ProxyChoice::FromEnvironment);
    let mut hosts: Vec<Arc<dyn Host>> = Vec::new();
    for form in forms {
        match HttpHost::new(form, dial.clone()) {
            Ok(host) => hosts.push(Arc::new(host)),
            Err(why) => say(format!("a file host left out: {why}")),
        }
    }
    if hosts.is_empty() {
        return Err("no file host of the list can be used".into());
    }
    let (mqtt, last) = (std::env::var(podssh_relay::code::MQTT_ENV).ok(), std::env::var(LAST_RESORT).ok());
    let brokers = podssh_relay::code::brokers(mqtt.as_deref(), last.as_deref());
    let config = podssh_relay::code::config(&trust, &ProxyChoice::FromEnvironment, say.clone());
    let board = MqttBoard::first(brokers, config)
        .ok_or_else(|| format!("no MQTT broker for its notes ({}=no, or none listed)", podssh_relay::code::MQTT_ENV))?;
    let board_name = board.name().to_string();
    let host_names = hosts.iter().map(|h| h.name().to_string()).collect();
    let keys = Arc::new(Keys::of_pair(name, token));
    let carrier = Arc::new(Carrier::new(keys, hosts, Arc::new(board), Gate::default(), say));
    Ok(Built { carrier, hosts: host_names, board: board_name })
}

/// The line of Q78 for the board, before its first note.
pub fn board_line(board: &str) -> String {
    format!(
        "the file-host road, the last of the last fallbacks: its notes (each piece's host and URL, sealed under \
         the pair's key) go through {board}, a public MQTT broker that nobody vouches for (the operator's ruling \
         Q78), which sees their topics, sizes and times; {ENV}=no or {LAST_RESORT}=no turns it off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTED: &[&str] = &["host-a", "host-b", "host-c"];

    #[test]
    fn podssh_filehosts_takes_the_unasked_hosts_names_others_or_turns_off() {
        let unasked = &LISTED[..2];
        let on = |ids: &[&str]| Setting::On(ids.iter().map(|id| id.to_string()).collect());
        assert_eq!(setting_of(None, None, LISTED, unasked), Ok(on(unasked)));
        assert_eq!(setting_of(Some(" yes "), None, LISTED, unasked), Ok(on(unasked)));
        assert_eq!(setting_of(Some("host-c,host-a"), None, LISTED, unasked), Ok(on(&["host-c", "host-a"])));
        assert_eq!(setting_of(Some("no"), None, LISTED, unasked), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), LISTED, unasked), Ok(Setting::Off(LAST_RESORT)));
        assert_eq!(setting_of(None, None, &[], &[]), Ok(Setting::Off("pod-services")));
        let why = setting_of(Some("elsewhere"), None, LISTED, unasked).unwrap_err();
        assert!(why.starts_with("PODSSH_FILEHOSTS: "), "{why}");
    }

    #[test]
    fn the_catalog_s_hosts_are_taken_unasked_where_their_terms_allow() {
        let (listed, unasked) = filehost::services::ids();
        match setting_of(None, None, &listed, &unasked) {
            Ok(Setting::On(ids)) => assert_eq!(ids, unasked),
            other => panic!("{other:?}"),
        }
        assert!(unasked.len() < listed.len(), "a host whose terms refuse automated uploads waits to be named");
    }

    #[test]
    fn the_board_s_line_names_it_the_third_party_and_both_switches() {
        let line = board_line("wss://broker.stand-in.test/");
        assert!(line.contains("broker.stand-in.test") && line.contains("nobody vouches for"), "{line}");
        assert!(line.contains("PODSSH_FILEHOSTS=no") && line.contains("PODSSH_LAST_RESORT=no"), "{line}");
    }
}
