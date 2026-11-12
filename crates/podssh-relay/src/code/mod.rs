//! Pairing by a short code (T-086): a node's host gives a code that a person
//! reads to the operator, who types it, and the two ends move what a pair's
//! file moved before: the operator's part of the pair and the node's key one
//! way, the operator's key the other. The code is used once and lives 10
//! minutes; it never crosses the network.
//!
//! The ends meet at a magic-wormhole mailbox, a WebSocket on port 443 that
//! needs no account (the operator's ruling Q65 lets podssh use the public
//! ones unasked; their terms are in docs/carriers.md), or at podssh's relay
//! role, which serves the same protocol (`crate::serve::mailbox`). The
//! mailbox stores and forwards ([`mailbox`]); the ends run SPAKE2 keyed by
//! the whole code over it, then seal each later message with a key of it
//! ([`wormhole`]), as magic-wormhole's own client does, so that a peer of its
//! Python library pairs with podssh's. The client, the code and its words
//! are `pod-wormhole`'s; podssh gives it the AppID, its name, its way out
//! and the mailboxes ([`config`]). The mailbox learns nothing of the
//! code and can change nothing, and an attacker who claims the code's
//! nameplate gets one guess of its 24 bits: the giver ends the code at the
//! first exchange, whatever its end ([`run`]). What the ends say and the
//! runs of the two ends are `pod-relay`'s ([`exchange`], T-684).

// The exchange and the runs of a code: pod-relay of PodUtils/podcrates.
pub use pod_relay::code::{exchange, run};

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};

pub use pod_wormhole::{mailbox, mqtt, phrase, words, wormhole, Code, Failed, WORDS};

/// podssh's application in the mailbox, as magic-wormhole asks each to name
/// one: nameplates and mailboxes of another application never meet it.
pub const APPID: &str = "github.com/PodUtils/podssh/pair";
/// The public mailboxes, in order: magic-wormhole's, on port 443 since its
/// commit "public_relay.py: use TLS" (2026-05-13), then Least Authority's:
/// the services of the kind `mailbox` of `pod-services`, by their rank.
pub fn public_mailboxes() -> Vec<String> {
    pod_services::of_kind("mailbox").filter_map(|s| s.endpoint("mailbox")).map(|e| e.url()).collect()
}
/// `no` turns pairing by code off; mailbox URLs, by commas, name others.
pub const ENV: &str = "PODSSH_PAIR_MAILBOX";
/// `no` gives the pairing no MQTT broker after the mailboxes (T-737).
pub const MQTT_ENV: &str = "PODSSH_MQTT";

/// The public MQTT brokers, after each mailbox (T-737, the operator's rulings
/// Q77 and Q78): the services of the kind `mqtt-broker` of `pod-services`, by
/// their rank, each with its public login. `PODSSH_MQTT=no`, or
/// `PODSSH_LAST_RESORT=no` (the last fallbacks of Q78), gives none; another
/// value of `PODSSH_MQTT` is no setting of its own and leaves them on.
pub fn brokers(mqtt: Option<&str>, last_resort: Option<&str>) -> Vec<mqtt::Point> {
    let no = |v: Option<&str>| {
        matches!(v.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("no" | "off" | "false" | "0"))
    };
    if no(mqtt) || no(last_resort) {
        return Vec::new();
    }
    pod_services::of_kind("mqtt-broker")
        .filter_map(|service| {
            let url = WsUrl::parse(&service.endpoint("broker")?.url()).ok()?;
            let login = match (service.text("user"), service.text("password")) {
                (Some(user), Some(password)) => Some(mqtt::Login { user: user.into(), password: password.into() }),
                _ => None,
            };
            Some(mqtt::Point { url, login })
        })
        .collect()
}
/// How long a code lives: past it the giver leaves, and the code fails.
pub const LIFETIME: Duration = Duration::from_secs(600);

/// Where the lines of a pairing go, for the user. No line holds the code.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The settings of each connection to a mailbox: podssh's AppID and name,
/// the way out of `proxy` with podssh's TLS and DNS, the roots of `trust`,
/// and the events of `say` as lines.
pub fn config(trust: &Trust, proxy: &ProxyChoice, say: Say) -> pod_wormhole::Config {
    let way = podssh_ws::client::way(proxy);
    let mut config = pod_wormhole::Config::new(APPID, "podssh", env!("CARGO_PKG_VERSION"), way);
    config.trust = trust.clone();
    config.connect_timeout = crate::open::CONNECT_TIMEOUT;
    config.events = Arc::new(move |event: pod_core::Event| say(event.text));
    config
}

/// The mailboxes to try, in order: the ones of `named` (`--pair-mailbox`),
/// else of the variable's `value`, else the public ones. `no` turns pairing
/// by code off, which is an error with the way that is left. A refusal does
/// not echo the text, as a URL's query may hold a secret.
pub fn mailboxes(named: Option<&str>, value: Option<&str>) -> Result<Vec<WsUrl>, String> {
    mailboxes_for(named, value, "give the operator's part as a file (podssh relay pair NAME --operator-file FILE)")
}

/// [`mailboxes`], with `way`, the way left when `no` turns the code off,
/// for each command that gives or takes one (T-616).
pub fn mailboxes_for(named: Option<&str>, value: Option<&str>, way: &str) -> Result<Vec<WsUrl>, String> {
    let (text, whose) = match named.map(str::trim).filter(|t| !t.is_empty()) {
        Some(text) => (text, "--pair-mailbox"),
        None => (value.map(str::trim).unwrap_or_default(), ENV),
    };
    match text.to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => public_mailboxes().iter().map(|url| WsUrl::parse(url)).collect(),
        "no" | "off" | "false" | "0" => Err(format!("{whose} no turns pairing by code off: {way}")),
        _ => text
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(|url| WsUrl::parse(url).map_err(|why| format!("{whose}: no, or mailboxes' URLs: {why}")))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_mailboxes_come_unless_a_flag_or_the_variable_names_others_or_no() {
        let public = mailboxes(None, None).unwrap();
        assert_eq!(public.len(), 2);
        assert_eq!((public[0].tls, public[0].host.as_str(), public[0].port), (true, "relay.magic-wormhole.io", 443));
        assert_eq!(public[1].host, "mailbox.mw.leastauthority.com");
        assert!(public.iter().all(|url| url.target == "/v1"));
        assert_eq!(mailboxes(None, Some(" yes ")).unwrap(), public);
        let own = mailboxes(None, Some("ws://127.0.0.1:4000/v1, wss://relay.example.org/v1/mailbox")).unwrap();
        assert_eq!(own.len(), 2);
        assert_eq!((own[0].tls, own[0].port), (false, 4000));
        assert_eq!(own[1].target, "/v1/mailbox");
        let flag = mailboxes(Some("wss://mine.example.org/v1/mailbox"), Some("no")).unwrap();
        assert_eq!(flag[0].host, "mine.example.org", "the flag wins over the variable");
        let off = mailboxes(None, Some("No")).unwrap_err();
        assert!(off.starts_with("PODSSH_PAIR_MAILBOX no turns pairing by code off"), "{off}");
        assert!(mailboxes(Some("off"), None).unwrap_err().starts_with("--pair-mailbox no"));
        let bad = mailboxes(None, Some("https://x.example/?key=SECRET")).unwrap_err();
        assert!(bad.starts_with("PODSSH_PAIR_MAILBOX: ") && !bad.contains("SECRET"), "{bad}");
        let net = mailboxes_for(None, Some("off"), "the net's own way").unwrap_err();
        assert_eq!(net, "PODSSH_PAIR_MAILBOX no turns pairing by code off: the net's own way");
        assert_eq!(mailboxes_for(None, None, "x").unwrap(), public);
    }

    /// The public broker of the catalog, with its login; none where either
    /// switch says no.
    #[test]
    fn the_public_brokers_come_unless_a_switch_says_no() {
        let public = brokers(None, None);
        assert!(!public.is_empty(), "the catalog lists no mqtt-broker");
        assert!(public.iter().all(|p| p.url.tls && p.url.port == 443 && p.login.is_some()), "{public:?}");
        assert!(!format!("{public:?}").contains("password: "), "a login's Debug hides its password");
        assert_eq!(brokers(Some("yes"), None).len(), public.len());
        assert!(brokers(Some(" No "), None).is_empty());
        assert!(brokers(None, Some("no")).is_empty());
    }
}
