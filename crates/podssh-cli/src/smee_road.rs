//! `PODSSH_SMEE` (T-741): the smee.io road of a pair, a last fallback of the
//! operator's ruling Q78 after the Piping Server road and OpenTunnel's, for
//! a proxy that refuses the WebSocket upgrade. Unset, empty or `yes`, the
//! road goes through the first server of the kind `smee` of `pod-services`
//! (smee.io, once that list names it; none before); `no` turns it off, and
//! so does `PODSSH_LAST_RESORT=no` (T-548's switch of each last fallback);
//! a server's `https://HOST[:PORT][/PREFIX]` names one of the user's own
//! (smee.io's server is free software), which `PODSSH_LAST_RESORT` leaves
//! on, as nobody else carries the session there.

use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::piping::Server;
use podssh_relay::smee::{http as smee_http, Dialer, Http, Node, Say, Secret};
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};

use crate::relay_settings::Refusal;

/// The variable of the road.
pub const ENV: &str = "PODSSH_SMEE";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = podssh_relay::pinggy::LAST_RESORT;

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that said so.
    Off(&'static str),
    /// The road through this server; whether it is the listed one, a third
    /// party's that nobody vouches for.
    On(Server, bool),
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the servers of `pod-services`. Another word is a
/// configuration error, which does not echo the value.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: &[Server]) -> Result<Setting, String> {
    let text = value.map(str::trim).unwrap_or_default();
    match text.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Setting::Off(ENV)),
        "" | "yes" | "on" | "true" | "1" => {
            if podssh_relay::pinggy::last_resort_off(last)? {
                return Ok(Setting::Off(LAST_RESORT));
            }
            Ok(listed.first().map_or(Setting::Off("pod-services"), |server| Setting::On(server.clone(), true)))
        }
        lower if lower.starts_with("https://") => Server::parse(text)
            .map(|server| Setting::On(server, false))
            .map_err(|_| format!("{ENV}: yes, no, or a smee.io server's https://HOST[:PORT][/PREFIX]")),
        _ => Err(format!("{ENV}: yes, no, or a smee.io server's https://HOST[:PORT][/PREFIX]")),
    }
}

/// The setting of this process's variables; a bad one is refused (78)
/// before anything connects.
pub fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref(), &podssh_relay::smee::listed()).map_err(Refusal::config)
}

/// The server of the road, when it is on; a bad setting reads as off here,
/// as [`setting`] refused it before the race.
pub fn server() -> Option<(Server, bool)> {
    match setting() {
        Ok(Setting::On(server, public)) => Some((server, public)),
        _ => None,
    }
}

/// The line of Q78, before the first byte goes to a listed server.
pub fn third_party_line(server: &Server) -> String {
    format!(
        "the smee.io road, the last fallback: {server}, a third party that nobody vouches for, carries this \
         session as events of its channels (the operator's ruling Q78); anyone who knows a channel's name sees \
         the times and the sizes, and SSH and the end-to-end channel keep the bytes private; {ENV}=no or \
         {LAST_RESORT}=no turns it off"
    )
}

/// The HTTP client of `server`, through the proxy of the environment.
pub fn http(server: &Server, trust: &Trust) -> Http {
    Http::new(server.clone(), smee_http::tls(trust.clone(), ProxyChoice::FromEnvironment))
}

/// A dialer of the node of the pair of `part` through `server`; its lines go
/// to `-v` under `shown`.
pub fn dialer(part: &OperatorPart, server: &Server, trust: &Trust, log: &Arc<Log>, shown: &str) -> Dialer {
    let say: Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    Dialer::new(Secret::of_pair(&part.name, part.connect_token()), http(server, trust), say)
}

/// The node of the road of the pair `name` with `token`, at `server`.
pub fn node(name: &str, token: &str, server: &Server, trust: &Trust, say: Say) -> Node {
    Node { secret: Arc::new(Secret::of_pair(name, token)), http: Arc::new(http(server, trust)), say }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed() -> Vec<Server> {
        vec![Server::parse("https://smee.example").unwrap()]
    }

    #[test]
    fn podssh_smee_takes_the_listed_server_unless_a_variable_names_one_or_turns_it_off() {
        let on = Setting::On(listed()[0].clone(), true);
        for unset in [None, Some(""), Some(" yes ")] {
            assert_eq!(setting_of(unset, None, &listed()), Ok(on.clone()), "{unset:?}");
        }
        assert_eq!(setting_of(Some("no"), None, &listed()), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), &listed()), Ok(Setting::Off(LAST_RESORT)), "the switch of Q78");
        assert_eq!(setting_of(None, None, &[]), Ok(Setting::Off("pod-services")), "no host of podssh's own");
        let own = setting_of(Some("https://smee.own.example:8443/s"), Some("no"), &[]).unwrap();
        assert_eq!(own, Setting::On(Server::parse("https://smee.own.example:8443/s").unwrap(), false));
        for bad in ["maybe", "http://smee.example", "https://secret@smee.example"] {
            let why = setting_of(Some(bad), None, &listed()).unwrap_err();
            assert!(why.starts_with("PODSSH_SMEE: ") && !why.contains("secret"), "{why}");
        }
    }

    #[test]
    fn the_line_names_the_server_the_third_party_and_both_switches() {
        let line = third_party_line(&listed()[0]);
        assert!(line.contains("smee.example") && line.contains("nobody vouches for"), "{line}");
        assert!(line.contains("PODSSH_SMEE=no") && line.contains("PODSSH_LAST_RESORT=no"), "{line}");
    }
}
