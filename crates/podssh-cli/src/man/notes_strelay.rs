//! The notes of Syncthing's relay road (T-571), a last fallback of the
//! operator's ruling Q78 after HyperDHT's road: a node of a pair joined to a
//! relay of Syncthing's pool on 443 under a certificate of the pair's own,
//! and a client that asks the relay for it. Only a build with the feature
//! `strelay` has it.

/// The note of `podssh node`, after HyperDHT's road's.
pub(super) const NODE: &str = "In a build with the feature strelay, a node of the pair's road with the \
     resumable layer and the end-to-end channel (no --plain, no --no-e2e) and a TCP TARGET also waits for \
     the pair's operators on a relay of Syncthing's pool, the last fallback of the operator's ruling Q78 \
     after HyperDHT's road: the relay on 443 that the SHA-256 of the pair's name picks among those that \
     podssh's list of services names (none while it names none), or the relay of PODSSH_SYNCTHING_RELAY \
     (a relay:// URL in the pool's form, with the relay's device ID: Syncthing's strelaysrv of your own), by \
     one TLS connection through \
     HTTPS_PROXY. Its certificate, whose SHA-256 is its device ID, comes from the pair's name and connect \
     token, so its operators find it with no word between the two ends; each session is a TCP connection \
     of its own to the relay, served with the resumable layer under the keeper of its other roads. It \
     joins again, after 1 s, doubled to 32 s, when its connection goes. Its line names the relay, and for \
     one of the pool says that it carries the sessions of this road and sees the two ends' certificates, \
     the times and the sizes; the channel keeps the bytes from it. PODSSH_SYNCTHING_RELAY=no turns the road \
     off, and PODSSH_LAST_RESORT=no turns off the pool's relays.";

/// The note of `podssh ssh`, after HyperDHT's road's.
pub(super) const SSH: &str = "In a build with the feature strelay, node://NAME also races Syncthing's \
     relay road of its pair (T-571), only once each road before it failed, after HyperDHT's road and before \
     the onion road, the last fallback of the operator's ruling Q78: a request with a fresh certificate to \
     the pair's relay (the one on 443 that the SHA-256 of its name picks among the pool's relays of \
     podssh's list of services, or the relay of PODSSH_SYNCTHING_RELAY) for the node's device ID, which both \
     ends make of the pair's connect token, then the session's own TCP connection to the relay. It waits \
     30 s at most. Before its first link through a relay of the pool, a line says that the relay carries the \
     session. PODSSH_SYNCTHING_RELAY=no or PODSSH_LAST_RESORT=no (for the pool's relays) turns it off, and \
     --no-e2e leaves it out. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow HyperDHT's road's, in node's and ssh's, and hold
    /// each claim of Q78's third party.
    #[test]
    fn the_notes_of_syncthing_s_relay_road_follow_hyperdht_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of Syncthing's relay road");
        assert_eq!(node[at - 1], super::super::notes_hyperdht::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of Syncthing's relay road");
        assert_eq!(ssh[at - 1], super::super::notes_hyperdht::SSH);
        for text in ["Q78", "PODSSH_LAST_RESORT=no", "PODSSH_SYNCTHING_RELAY=no", "feature strelay", "SHA-256", "443"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("device ID"));
    }
}
