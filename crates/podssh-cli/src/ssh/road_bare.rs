//! The Bare hop of `podssh ssh node://NAME` (T-740), the last of all the
//! fallbacks of the operator's ruling Q78: the tunnel's name of the road of
//! `ssh -R` (`super::ssh_http`), reached through a Bare v3 node
//! (`podssh_ws::bare`) in place of directly, once each road before it
//! failed. A proxy on the way sees the node's name alone, where it may have
//! refused the tunnel's. Only that road: its WebSocket carries no credential,
//! where a relay's carries a token, which never goes to a third party (as
//! none goes to a forwarder, T-370). The node is the first of the kind
//! `bare-node` of `pod-services` (`openbare.xyz` now), never a host in this
//! repository, or the one of `PODSSH_BARE`; `PODSSH_BARE=no` or
//! `PODSSH_LAST_RESORT=no` turns the hop off. The node dials the far host
//! itself: it sees the tunnel's name, the times and the sizes, and the
//! end-to-end channel keeps the bytes.

use podssh_relay::pinggy::{last_resort_off, LAST_RESORT};
use podssh_ws::url::WsUrl;

use crate::relay_settings::Refusal;

/// The variable of the hop.
pub(crate) const ENV: &str = "PODSSH_BARE";

/// The kind of `pod-services` whose services are Bare nodes, and the name
/// of a node's endpoint.
const KIND: &str = "bare-node";
const ENDPOINT: &str = "bare";

/// The node of `pod-services`: its endpoint `bare`, `https://HOST:PORT/PATH`,
/// as the node's WebSocket `wss://HOST:PORT/PATH`.
fn hosted() -> Option<WsUrl> {
    let service = pod_services::of_kind(KIND).next()?;
    let endpoint = service.endpoint(ENDPOINT)?;
    let path = endpoint.path().unwrap_or("/");
    WsUrl::parse(&format!("wss://{}{path}", podssh_ws::dial::authority(endpoint.host(), endpoint.port()))).ok()
}

/// The node of the variables `value` (of [`ENV`]) and `last` (of
/// [`LAST_RESORT`]): none when either turns the hop off or no node is
/// named; an `https://` URL names one. Another word is a configuration
/// error (78), which does not echo the value.
pub(crate) fn node_of(value: Option<&str>, last: Option<&str>, hosted: Option<WsUrl>) -> Result<Option<WsUrl>, String> {
    if last_resort_off(last)? {
        return Ok(None);
    }
    let text = value.map(str::trim).unwrap_or_default();
    match text.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(None),
        "" | "yes" | "on" | "true" | "1" => Ok(hosted),
        lower if lower.starts_with("https://") => WsUrl::parse(&format!("wss://{}", &text["https://".len()..]))
            .map(Some)
            .map_err(|_| format!("{ENV}: yes, no, or a Bare node's https:// URL")),
        _ => Err(format!("{ENV}: yes, no, or a Bare node's https:// URL")),
    }
}

/// The node of this process's variables.
pub(crate) fn node() -> Result<Option<WsUrl>, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    node_of(value.as_deref(), last.as_deref(), hosted()).map_err(Refusal::config)
}

/// The far WebSocket of a tunnel's name, as the road of `ssh -R` dials it.
pub(crate) fn far(name: &str) -> Result<WsUrl, String> {
    WsUrl::parse(&format!("wss://{name}/"))
}

/// The line of Q78, before the first byte goes to the node.
pub(crate) fn line(node: &WsUrl, far: &WsUrl) -> String {
    format!(
        "the Bare hop, the last fallback: the Bare node {}, a third party that nobody vouches for, carries this \
         session to {} (the operator's ruling Q78); it sees that name, the times and the sizes, and the end-to-end \
         channel keeps the bytes private; {ENV}=no or {LAST_RESORT}=no turns it off",
        node.shown(),
        far.shown()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_is_pod_services_one_unless_a_variable_names_or_turns_it_off() {
        let listed = hosted().expect("pod-services names a bare-node");
        assert!(listed.tls && listed.target.starts_with('/'), "{listed:?}");
        assert_eq!(node_of(None, None, Some(listed.clone())), Ok(Some(listed.clone())));
        assert_eq!(node_of(Some("no"), None, Some(listed.clone())), Ok(None));
        assert_eq!(node_of(None, Some("no"), Some(listed.clone())), Ok(None), "the switch of each last fallback");
        let named = node_of(Some("https://bare.example/b/"), None, None).unwrap().unwrap();
        assert_eq!((named.host.as_str(), named.port, named.target.as_str()), ("bare.example", 443, "/b/"));
        let bad = node_of(Some("ftp://secret.example"), None, None).unwrap_err();
        assert!(!bad.contains("secret"), "the value is not echoed: {bad}");
        assert_eq!(node_of(None, None, None), Ok(None), "no node listed and none named");
    }

    #[test]
    fn the_line_names_the_node_and_the_far_name() {
        let (node, far) = (WsUrl::parse("wss://bare.example/bare/").unwrap(), far("t1.lhr.life").unwrap());
        let said = line(&node, &far);
        assert!(said.contains("wss://bare.example/bare/") && said.contains("wss://t1.lhr.life/"), "{said}");
        assert!(said.contains("nobody vouches for") && said.contains("PODSSH_BARE=no"), "{said}");
    }
}
