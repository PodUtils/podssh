//! The notes of ZeroTier's road (T-733), a last fallback of the operator's
//! ruling Q78: a node of a pair that holds a member of the pair's own
//! ad-hoc network through ZeroTier Inc.'s roots and TCP relay, and a client
//! that reaches it there. Only a build with the feature `zerotier` has it.

/// The note of `podssh node`, after croc's relay road's.
pub(super) const NODE: &str = "In a build with the feature zerotier, a node of the pair's road with the \
     resumable layer and the end-to-end channel (no --plain, no --no-e2e) and a TCP TARGET also waits for \
     the pair's operators on ZeroTier, the last fallback of the operator's ruling Q78 after croc's relay: \
     ZeroTierOne's own core, linked into podssh, joins an ad-hoc network of the pair's own (no controller, \
     no account) through ZeroTier Inc.'s roots and its TCP relay, which podssh's list of services names, or \
     the relay of PODSSH_ZEROTIER (IP:PORT, ZeroTierOne's tcp-proxy of your own), by one TCP connection \
     through HTTPS_PROXY. The node's ZeroTier identity, its address and the network's one port come from \
     the pair's name and connect token, so its operators know them with no word between the two ends; the \
     node waits at its 6plane address there, serves each connection with the resumable layer under the \
     keeper of its other roads, and dials the relay again, after 1 s, doubled to 32 s, when it goes. Its \
     line names the relay and says that ZeroTier Inc.'s roots and relay carry the sessions of this road and \
     see the two ZeroTier addresses, the times and the sizes; the channel keeps the bytes from them. \
     PODSSH_ZEROTIER_PLANET names a planet of your own roots in the place of ZeroTier Inc.'s. \
     PODSSH_ZEROTIER=no or PODSSH_LAST_RESORT=no turns the road off.";

/// The note of `podssh ssh`, after croc's relay road's.
pub(super) const SSH: &str = "In a build with the feature zerotier, node://NAME also races ZeroTier's road \
     of its pair (T-733), only once each road before it failed, after croc's relay road and the Pinggy road \
     and before the Serveo road, the last fallback of the operator's ruling Q78: a member of the pair's own \
     ad-hoc network, with a ZeroTier identity made for the run, through ZeroTier Inc.'s roots and TCP relay \
     (or those of PODSSH_ZEROTIER and PODSSH_ZEROTIER_PLANET), to the node's address, which both ends make \
     of the pair's connect token; it waits 60 s at most for the node to answer. Before its first link through \
     ZeroTier Inc.'s relay, a line says that ZeroTier Inc.'s roots and relay carry the session. \
     PODSSH_ZEROTIER=no or PODSSH_LAST_RESORT=no turns it off, and --no-e2e leaves it out. podssh ping \
     node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow croc's relay road's, in node's and ssh's, and hold
    /// each claim of Q78's third party.
    #[test]
    fn the_notes_of_zerotier_s_road_follow_croc_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of ZeroTier's road");
        assert_eq!(node[at - 1], super::super::notes_croc::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of ZeroTier's road");
        assert_eq!(ssh[at - 1], super::super::notes_croc::SSH);
        for text in ["Q78", "PODSSH_LAST_RESORT=no", "PODSSH_ZEROTIER=no", "PODSSH_ZEROTIER_PLANET", "zerotier"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("ZeroTier Inc."));
    }
}
