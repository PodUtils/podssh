//! The srv.us road of `podssh ssh node://NAME` (T-566), a last fallback of
//! the operator's ruling Q78: a WebSocket at `/` of the node's tunnel at
//! srv.us, whose name srv.us derives from the key that the node's leg logs
//! in with (`podssh_relay::ssh_http::srv_us`), the node's own. So the client
//! derives the name from the key that the end-to-end channel checks
//! (`--node-key`, else the net's, else the pins' of NAME), as the ssh-j road
//! does, with no record and no word of the node's: it needs the whole key,
//! not its fingerprint alone, which hashes nothing that srv.us hashed. The
//! zone is the server's own name (srv.us's names are under its domain), from
//! `pod-services` or `PODSSH_SRV_US`. It races last, once each road before it
//! failed, after the tunnel of `ssh -R` of a name given, kept or recorded
//! (`super::super::ssh_http`), and never with `--no-e2e`. Before its first
//! link, a line names srv.us as a third party that nobody vouches for. The
//! link is the one of a tunnel's name (`podssh_ws::cloudflare::connect`):
//! TLS on 443 through `HTTPS_PROXY`, verified by this host's roots.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::identity::KeyName;
use podssh_relay::session::race::Start;
use podssh_relay::ssh_http::{self, srv_us, Setting, SRV_US};
use podssh_ssh::Log;
use podssh_ws::client::DEFAULT_IDLE_TIMEOUT;
use podssh_ws::cloudflare::{self, Access};
use podssh_ws::{ProxyChoice, Trust};

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The name of the node `label` at srv.us, where the road is on with a
/// server and the node's whole key is known; else why not, for `-v`.
fn derived(label: &str, ask: &crate::channel::Ask) -> Result<String, &'static str> {
    let Ok(Setting::On(service)) = ssh_http::from_env(SRV_US) else { return Err("") };
    if ask.off {
        return Err("");
    }
    match crate::ssh::sshj::node_key(label, ask) {
        Some(KeyName::Key(key)) => Ok(srv_us::name(&key, &service.host)),
        Some(_) => Err("no srv.us road: the node's name there needs its whole key, and only its fingerprint is known"),
        None => Err("no srv.us road: no key of the node to derive its name from"),
    }
}

/// Whether the road to `label` would race: on, a whole key of the node,
/// and an end-to-end channel (`ask.off` is --no-e2e).
pub(crate) fn named(label: &str, ask: &crate::channel::Ask) -> bool {
    derived(label, ask).is_ok()
}

/// The road to the node of one run.
pub(crate) struct SrvUsRoads {
    name: String,
    trust: Trust,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl SrvUsRoads {
    /// The road to the node `label`, when [`named`]; else none, and `-v`
    /// says why where the road is on.
    pub(crate) fn new(
        label: &str,
        ask: &crate::channel::Ask,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<SrvUsRoads> {
        let name = match derived(label, ask) {
            Ok(name) => name,
            Err(why) => {
                if !why.is_empty() {
                    log.verbose(&format!("{shown}: {why}"));
                }
                return None;
            }
        };
        let (trust, log, shown) = (trust.clone(), log.clone(), shown.to_string());
        Some(SrvUsRoads { name, trust, said: AtomicBool::new(false), log, shown })
    }

    /// The road's place in the race: last, once each road before it failed (Q78).
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::SrvUs);
    }

    async fn link(&self) -> Result<Road, String> {
        let name = &self.name;
        if let Ok(Setting::Off(by)) = ssh_http::from_env(SRV_US) {
            return Err(format!("wss://{name}/: {by}=no turns the srv.us road off"));
        }
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, ssh_http::client_line(SRV_US, name)));
            let dials = format!("the srv.us road dials wss://{name}/, the name of the node's key");
            self.log.verbose(&format!("{}: {dials}", self.shown));
        }
        let (access, proxy, limit) =
            (Access::default(), ProxyChoice::FromEnvironment, podssh_relay::open::CONNECT_TIMEOUT);
        match cloudflare::connect(name, &access, &self.trust, &proxy, limit, Some(DEFAULT_IDLE_TIMEOUT)).await {
            Ok(session) => Ok(Road::SshHttp(podssh_ssh::relay_stream::spawn(session).0)),
            Err(e) => Err(format!("wss://{name}/: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_alone_names_no_srv_us_tunnel_and_no_e2e_none_at_all() {
        let key = podssh_relay::identity::Identity::from_seed(&[5; 32]).public();
        let print = KeyName::parse(&key.fingerprint()).expect("a fingerprint");
        let ask =
            |node_key: Option<KeyName>, off: bool| crate::channel::Ask { client_key: None, node_key, off, route: None };
        // With no server of the word in this build, the road is off whatever the key.
        if let Ok(Setting::On(service)) = ssh_http::from_env(SRV_US) {
            assert_eq!(derived("lab", &ask(Some(KeyName::Key(key)), false)), Ok(srv_us::name(&key, &service.host)));
            assert!(derived("lab", &ask(Some(print), false)).unwrap_err().contains("whole key"));
        }
        assert!(!named("lab", &ask(Some(KeyName::Key(key)), true)), "never with --no-e2e");
    }
}
