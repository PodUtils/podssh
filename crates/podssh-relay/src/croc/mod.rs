//! croc's relay road (T-694): a carrier of a pair's road through croc's
//! public relays, reached on port 443 through the WebSocket bridge of
//! `croc-web` at `wss://getcroc.com/ws`, which pipes each binary message to
//! the relay that its query names (schollz/croc:src/webrelay/webrelay.go at
//! v11.6.4). A relay pairs the two members of a room once each passed its
//! handshake ([`relay`]: a PAKE on the curve SIEC with a public weak key,
//! [`pake`], [`siec`], and croc's crypt, [`crypt`]), then pipes their raw
//! bytes ([`wire`]). The rooms, the relay of croc's pool and the proof of
//! the pair come from the pair's connect token, which both ends hold
//! ([`rooms`]); a node waits in a room ([`far`]), and a client meets it
//! there for each link ([`client`], [`meet`]). A link is the transit road's
//! byte stream over one WebSocket (`crate::transit::Link`): each session
//! over it runs the resumable layer and, above the layer, the end-to-end
//! channel (`crate::e2e`), so the bridge and the relay are trusted for
//! availability only.
//!
//! A last fallback of the operator's ruling Q78: croc's relays are a
//! volunteer's, with no terms for this use (read on 2026-11-10; T-694's
//! Decision), so the road is tried after each other road, and a line names
//! them as third parties that nobody vouches for. The default bridge is
//! the service `croc` of `pod-services`; while the list holds none, the
//! road needs a bridge named in [`ENV`].

pub mod client;
pub mod crypt;
pub mod far;
pub mod meet;
pub mod pake;
pub mod relay;
pub mod rooms;
pub mod siec;
pub mod wire;

use std::sync::Arc;

use podssh_ws::url::WsUrl;

pub use client::{carry, Dialer};
pub use far::Node;
pub use meet::Missed;
pub use rooms::Rooms;

/// `no` turns the road off; a `wss://` URL names another bridge (croc-web of
/// the user's own, whose `/ws` reaches the user's `croc relay`).
pub const ENV: &str = "PODSSH_CROC";
/// The switch of each last fallback (Q78), as the Pinggy road reads it.
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// croc's public relays behind the bridge: `1.getcroc.com` to `4.getcroc.com`
/// (src/publicrelay/publicrelay.go at v11.6.4), which the bridge names by
/// their index alone.
pub const RELAYS: usize = 4;
/// The relay's port where rooms are made: croc's control port, 9009, the
/// first of the bridge's allowlist (9009 to 9017). Each port is a relay of
/// its own, so both ends take this one.
pub const PORT: u16 = 9009;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// A bridge to croc's relays, and what each link asks of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    /// The bridge's WebSocket, `/ws` of croc-web.
    pub url: WsUrl,
    /// The relays behind it, of which a pair's rooms pick one.
    pub relays: usize,
    /// The relays' password.
    pub password: String,
    /// The default of `pod-services`: a third party's, whose line says so.
    pub public: bool,
}

impl Bridge {
    /// A bridge that the user named: its URL's query, when it has one, is
    /// taken as given (`?relay=N&port=P`); else its one relay, at index 0.
    pub fn named(url: WsUrl) -> Bridge {
        Bridge { url, relays: 1, password: relay::PASSWORD.to_string(), public: false }
    }

    /// The bridge of `pod-services`' service `croc`, when the list has one.
    pub fn listed() -> Option<Bridge> {
        let service = pod_services::get("croc")?;
        let url = WsUrl::parse(&service.endpoint("bridge")?.url()).ok()?;
        let relays = service.int("relays").and_then(|n| usize::try_from(n).ok()).filter(|n| *n > 0);
        let password = service.text("password").unwrap_or(relay::PASSWORD).to_string();
        Some(Bridge { url, relays: relays.unwrap_or(RELAYS), password, public: true })
    }

    /// The URL of the relay of `rooms`, through the bridge.
    pub fn url(&self, rooms: &Rooms) -> WsUrl {
        if self.url.target.contains('?') {
            return self.url.clone();
        }
        let target = format!("{}?relay={}&port={PORT}", self.url.target, rooms.relay(self.relays));
        WsUrl { target, ..self.url.clone() }
    }

    /// The relay as a line names it: its index, through the bridge.
    pub fn shown(&self, rooms: &Rooms) -> String {
        match self.url.target.contains('?') {
            true => format!("croc's relay through {}", self.url.shown()),
            false => format!("croc's relay {} through {}", rooms.relay(self.relays), self.url.shown()),
        }
    }
}

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and why: the variable that turned it off, or `pod-services`,
    /// which names no bridge.
    Off(&'static str),
    /// The road, through this bridge.
    On(Bridge),
}

/// Whether a switch's value says no: unset, empty or yes is on.
fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// [`ENV`]'s `value` and [`LAST_RESORT`]'s `last`: no, none; a `ws://` or
/// `wss://` URL, that bridge, which is the user's and so not a last fallback;
/// unset, empty or yes, the bridge of `pod-services`, which [`LAST_RESORT`]
/// turns off (a word that is neither yes nor no is no there, as the switch
/// of the third parties fails closed). Another word is refused, without its
/// text, as a URL's query may hold a secret.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    match says_no(value) {
        Some(true) => Ok(Setting::Off(ENV)),
        Some(false) if says_no(last) != Some(false) => Ok(Setting::Off(LAST_RESORT)),
        Some(false) => Ok(Bridge::listed().map_or(Setting::Off("pod-services"), Setting::On)),
        None => {
            let text = value.map(str::trim).unwrap_or_default();
            let url = WsUrl::parse(text).map_err(|why| format!("{ENV}: yes, no, or a bridge's URL: {why}"))?;
            Ok(Setting::On(Bridge::named(url)))
        }
    }
}

/// The line that a run says before croc's public relay carries a session of
/// its own (Q78).
pub fn third_party_line(shown: &str) -> String {
    format!(
        "croc's relay road, a last fallback: {shown}, a volunteer's service that nobody vouches for, carries \
         this session (the operator's ruling Q78); SSH and the end-to-end channel keep its bytes private; \
         {ENV}=no or {LAST_RESORT}=no turns it off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variables_turn_the_road_off_name_a_bridge_or_are_refused_without_their_text() {
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting(Some(off), None), Ok(Setting::Off(ENV)), "{off}");
        }
        // The default is pod-services' bridge, or off while the list names none.
        let default = setting(None, None).unwrap();
        assert!(matches!(&default, Setting::On(bridge) if bridge.public) || default == Setting::Off("pod-services"));
        assert_eq!(setting(Some("yes"), Some("no")), Ok(Setting::Off(LAST_RESORT)));
        assert_eq!(setting(None, Some("maybe")), Ok(Setting::Off(LAST_RESORT)), "fails closed");
        let own = setting(Some("ws://127.0.0.1:9014/ws"), Some("no")).unwrap();
        let Setting::On(bridge) = own.clone() else { panic!("a bridge named is the user's: {own:?}") };
        assert!(!bridge.public && bridge.relays == 1 && bridge.password == "pass123");
        let refused = setting(Some("https://h/ws?key=SECRET"), None).unwrap_err();
        assert!(refused.starts_with("PODSSH_CROC: ") && !refused.contains("SECRET"), "{refused}");
    }

    #[test]
    fn a_link_names_the_relay_that_the_rooms_pick_and_the_control_port() {
        let rooms = Rooms::of_pair("0123456789abcdef0123456789abcdef", "connect-token-of-a-test-0123456789abcdef");
        let public =
            Bridge { relays: RELAYS, public: true, ..Bridge::named(WsUrl::parse("wss://b.example/ws").unwrap()) };
        assert_eq!(public.url(&rooms).target, "/ws?relay=1&port=9009");
        assert_eq!(public.shown(&rooms), "croc's relay 1 through wss://b.example/ws");
        let own = Bridge::named(WsUrl::parse("wss://own.example/ws").unwrap());
        assert_eq!(own.url(&rooms).target, "/ws?relay=0&port=9009");
        let given = Bridge::named(WsUrl::parse("wss://own.example/ws?relay=2&port=9010").unwrap());
        assert_eq!(given.url(&rooms).target, "/ws?relay=2&port=9010");
        assert_eq!(given.shown(&rooms), "croc's relay through wss://own.example/ws");
        let line = third_party_line(&public.shown(&rooms));
        assert!(line.contains("nobody vouches for") && line.ends_with("PODSSH_LAST_RESORT=no turns it off"));
    }
}
