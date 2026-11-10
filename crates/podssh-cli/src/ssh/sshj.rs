//! The ssh-j road of `podssh ssh node://NAME` (T-570), a last fallback of
//! the operator's ruling Q78: ssh-j.com as the first hop, as `ssh -J
//! USER@ssh-j.com ADDRESS` takes it, to the name that the node's key gives
//! (`crate::sshj::name`). The key is the one that the end-to-end channel
//! checks: `--node-key`, else the key that the net names for NAME, else the
//! key that the pins of NAME hold from an earlier session; with none, the
//! road does not race, as no name can be derived. It races last of all,
//! once each road before it failed, and never with `--no-e2e`, as the server
//! ends the leg's SSH and would see each byte. Before its first link, a line
//! names the server as a third party that nobody vouches for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::identity::KeyName;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use super::road_link::{Kind, Road};
use super::roads::Going;
use crate::sshj::{self, JumpName, Service, Setting};

/// The key of the node `label`: `--node-key`, the net's, or the pins'.
fn node_key(label: &str, ask: &crate::channel::Ask) -> Option<KeyName> {
    if let Some(named) = &ask.node_key {
        return Some(named.clone());
    }
    if let Some(member) = crate::net::lookup::member(label) {
        return Some(member.key);
    }
    pinned(label)
}

/// The first key that the pins hold for `label`, where their file can be
/// trusted, as the channel reads it (`known-nodes`: `LABEL KEY` lines).
fn pinned(label: &str) -> Option<KeyName> {
    use podssh_relay::cache::{pod_places, read_own, Others};
    for dir in pod_places().read() {
        match read_own(&dir.join(podssh_relay::identity::pins::FILE), Others::Read) {
            Ok(Some(text)) => return first_pin(&text, label),
            Ok(None) => {}
            // A file that cannot be trusted names no key: the channel refuses it too.
            Err(_) => return None,
        }
    }
    None
}

/// The key of the first line of `label` in the text of the pins.
fn first_pin(text: &str, label: &str) -> Option<KeyName> {
    text.lines().filter(|line| !line.trim_start().starts_with('#')).find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some(label)).then(|| words.next().and_then(KeyName::parse)).flatten()
    })
}

/// Whether the road to `label` would race: on with a server, a key to
/// derive the name from, and an end-to-end channel (`ask.off` is --no-e2e).
pub(crate) fn named(label: &str, ask: &crate::channel::Ask) -> bool {
    !ask.off && matches!(sshj::from_env(), Ok(Setting::On(_))) && node_key(label, ask).is_some()
}

/// The road to the node of one run.
pub(crate) struct SshJRoads {
    service: Service,
    name: JumpName,
    trust: Trust,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl SshJRoads {
    /// The road to the node `label`, when [`named`]; else none, and `-v`
    /// says why where the road is on.
    pub(crate) fn new(
        label: &str,
        ask: &crate::channel::Ask,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<SshJRoads> {
        let Ok(Setting::On(service)) = sshj::from_env() else { return None };
        if ask.off {
            return None;
        }
        let Some(key) = node_key(label, ask) else {
            log.verbose(&format!("{shown}: no ssh-j road: no key of the node to derive its name from"));
            return None;
        };
        let name = JumpName::of(&key);
        let (log, shown, trust) = (log.clone(), shown.to_string(), trust.clone());
        Some(SshJRoads { service, name, trust, said: AtomicBool::new(false), log, shown })
    }

    /// The road's place in the race: last, once each road before it failed (Q78).
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::SshJ);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, sshj::third_party_line(&self.service)));
            self.log.verbose(&format!("{}: the ssh-j road dials {} at {}", self.shown, self.name, self.service));
        }
        let say = {
            let (log, shown) = (self.log.clone(), self.shown.clone());
            move |line: String| log.verbose(&format!("{shown}: {line}"))
        };
        sshj::client::link(&self.service, &self.name, &self.trust, &self.log, &say).await.map(Road::SshJ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pins_give_the_first_key_of_the_label_and_skip_comments_and_others() {
        let key = podssh_relay::identity::Identity::from_seed(&[3; 32]).public();
        let other = podssh_relay::identity::Identity::from_seed(&[4; 32]).public();
        let text = format!("# lab {other}\nlabby {other}\nlab {}\nlab {other}\n", key.fingerprint());
        assert_eq!(first_pin(&text, "lab").map(|k| k.fingerprint()), Some(key.fingerprint()));
        assert_eq!(first_pin(&text, "none"), None);
        assert_eq!(first_pin("lab not-a-key\n", "lab"), None);
    }
}
