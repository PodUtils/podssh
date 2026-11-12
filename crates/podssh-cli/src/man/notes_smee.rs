//! The notes of the smee.io road (T-741), a last fallback of the operator's
//! ruling Q78 after the onion road: a node of a pair that reads its door's
//! channel at smee.io's server, and a client that posts a hello there, then
//! a POST for each frame and a stream of server-sent events back, each way
//! on a channel of its own.

/// The note of `podssh node`, after the onion road's.
pub(super) const NODE: &str = "A node of the pair's road with the resumable layer and the end-to-end channel \
     (no --plain, no --no-e2e) and a TCP TARGET also waits for the pair's operators at smee.io's server, the \
     last fallback of the operator's ruling Q78 after the onion road, for a proxy that refuses the WebSocket \
     upgrade: the server of podssh's list of services (none while it names none), or the one of PODSSH_SMEE \
     (https://HOST[:PORT][/PREFIX], smee.io's server of your own), over HTTPS by name on 443 through \
     HTTPS_PROXY, with no account and no upgrade. It reads its door, a channel whose name comes from the \
     pair's name and connect token, as a stream of server-sent events; a client's hello there names a link, \
     and each end then posts its way, one numbered frame of base64 in JSON at a time, to a channel of that \
     way, and reads the other's. While a link runs the door waits, so the node holds two connections at \
     most. Its line names the server, and for the listed one says that it carries the sessions of this \
     road and that anyone who knows a channel's name sees the times and the sizes; the channel keeps the \
     bytes. PODSSH_SMEE=no or PODSSH_LAST_RESORT=no (for the listed server) turns the road off.";

/// The note of `podssh ssh`, after the onion road's.
pub(super) const SSH: &str = "node://NAME also races the smee.io road of its pair (T-741), only once each \
     road before it failed, after the onion road and before the Serveo road, the last fallback of the \
     operator's ruling Q78: a stream of server-sent events of its way down at smee.io's server on 443 (the \
     listed one, or the one of PODSSH_SMEE), a hello at the node's door posted again each 3 s until the node's mark \
     comes, 20 s at most, then a POST for each frame up, each one after the answer to the one before. A \
     stream that gives no event within 15 s, as through a proxy that holds an answer until its end, ends the \
     road for the run. Before its first link through the listed server, a line says that the server carries \
     the session. PODSSH_SMEE=no or PODSSH_LAST_RESORT=no (for the listed server) turns it off, and \
     --no-e2e leaves it out. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow the onion road's, in node's and ssh's, and hold each
    /// claim of Q78's third party.
    #[test]
    fn the_notes_of_the_smee_io_road_follow_the_onion_road_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the smee.io road");
        assert_eq!(node[at - 1], super::super::notes_onion::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the smee.io road");
        assert_eq!(ssh[at - 1], super::super::notes_onion::SSH);
        for text in ["Q78", "PODSSH_LAST_RESORT=no", "PODSSH_SMEE=no", "443", "T-741"] {
            assert!(super::NODE.contains(text) || text == "T-741", "{text}");
            assert!(super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("two connections"));
    }
}
