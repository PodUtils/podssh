//! The notes of HyperDHT's road (T-736), where UDP passes, by the operator's
//! rulings Q77 and Q82, after Yggdrasil's road: a node of a pair that
//! announces a topic of a key of the pair's own in HyperDHT, and a client
//! that connects to it by that key, a hole punched through both NATs. Only a
//! build with the feature `hyperdht` has it.

/// The note of `podssh node`, after Yggdrasil's road's.
pub(super) const NODE: &str = "In a build with the feature hyperdht, a node of the pair's road with the \
     resumable layer and the end-to-end channel (no --plain, no --no-e2e) and a TCP TARGET also waits for \
     the pair's operators in HyperDHT where UDP passes, by the operator's rulings Q77 and Q82, after \
     Yggdrasil's road: it joins the DHT through the bootstrap nodes that podssh's list of services names \
     (none while it names none), or those of PODSSH_HYPERDHT (HOST:PORT[,HOST:PORT...], a DHT of your own), \
     under a key that the pair's name and connect token make, and announces a topic of that key, so its \
     operators find it with no word between the two ends. Each connection, a hole punched through both NATs \
     and a Noise channel over UDX, is served with the resumable layer under the keeper of its other roads. \
     Where no bootstrap node answers within 15 s, UDP does not pass: the node says so and serves its other \
     roads. Its line says that the DHT's nodes see the node's address and topic; the channel keeps the bytes \
     from them. PODSSH_HYPERDHT=no turns the road off, and PODSSH_LAST_RESORT=no turns off the public DHT.";

/// The note of `podssh ssh`, after Yggdrasil's road's.
pub(super) const SSH: &str = "In a build with the feature hyperdht, node://NAME also races HyperDHT's road \
     of its pair (T-736), where UDP passes, only once each road before it failed, after Yggdrasil's road and \
     before Syncthing's relay road, by the operator's rulings Q77 and Q82: this end joins HyperDHT with a fresh key, \
     once a run, through the bootstrap of podssh's list of services or of PODSSH_HYPERDHT, looks up the topic \
     of the node's key, which both ends make of the pair's connect token, again each 5 s, and connects by \
     that key. It waits 45 s at most; where no bootstrap node answers within 15 s, UDP does not pass, and the \
     road fails with that word. Before it joins the public DHT, a line says that the DHT's nodes see this \
     end's address. PODSSH_HYPERDHT=no or PODSSH_LAST_RESORT=no (for the public DHT) turns it off, and \
     --no-e2e leaves it out. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow Yggdrasil's road's, in node's and ssh's, and hold
    /// each claim of the rulings.
    #[test]
    fn the_notes_of_hyperdht_s_road_follow_yggdrasil_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of HyperDHT's road");
        assert_eq!(node[at - 1], super::super::notes_ygg::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of HyperDHT's road");
        assert_eq!(ssh[at - 1], super::super::notes_ygg::SSH);
        for text in
            ["Q77", "Q82", "PODSSH_LAST_RESORT=no", "PODSSH_HYPERDHT=no", "feature hyperdht", "UDP does not pass"]
        {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("topic"));
    }
}
