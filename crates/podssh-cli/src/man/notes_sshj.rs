//! The notes of the ssh-j road (T-570), the last fallback of the operator's
//! ruling Q78, after Serveo's: a node at a public SSH jump server under a name that its key
//! gives, and a client that derives the name and jumps to it.

/// The note of `podssh node NAME TARGET --ssh-j`.
pub(super) const NODE: &str = "With --ssh-j, the node serves TARGET over the ssh-j road: ssh-j.com, a public \
     SSH jump and forwarding server with no account, where podssh's list of services names it, or the server of \
     PODSSH_SSH_J (HOST[:PORT]); with neither, --ssh-j is a configuration error (78). The node's leg is SSH to the \
     server on port 22, directly or through HTTPS_PROXY's CONNECT, as a user that its key gives (podssh-, then 16 \
     hex digits), with one remote forward of a name that its key gives too (n, then 16 hex digits), on port 22, \
     as ssh -R NAME:22:... asks it there; its line ssh-j name says USER@NAME and the command of a client. A \
     client that holds the node's key derives the same name, so neither says it to the other and no record is \
     needed; the name stays across the node's starts. The server ends that SSH: it sees the times, the sizes \
     and the layer's bytes, which the end-to-end channel keeps from it. Its host key is checked against the one \
     that podssh's list of services names, where it names one; else any key passes, and the line says so. Anyone \
     may take any name there, so the road needs the end-to-end channel and a door: --allow, or the members of \
     the net held here when the node's key is one; never --plain, --no-e2e, --exit, a udp: TARGET, or \
     --opentunnel, --pinggy, --serveo, --iroh or --derp (64). The server keeps a name for the session that holds it: a \
     leg that ends is opened again, with a wait that doubles from 1 s to 60 s, and the sessions that the layer \
     keeps go on over the next; a name that a stranger holds first is refused to the node, which tries again, \
     and a client that reaches the stranger is refused by the end-to-end channel. The road is served alone: a \
     pair of NAME is not served beside it, and a line says so. A node that would serve the OpenTunnel road, \
     the Pinggy road or the Serveo road unasked serves this one, before the last roads that follow it, when none of them reached a \
     service, or when each is turned off, by the operator's ruling Q78, and its lines say so and name the \
     third party, which nobody vouches for. PODSSH_SSH_J=no turns the road off, and so does \
     PODSSH_LAST_RESORT=no, the switch of each last fallback.";

/// The note of `podssh ssh node://NAME` on the ssh-j road.
pub(super) const SSH: &str = "node://NAME races the ssh-j road too, last, before the roads that follow it, once each road before it \
     failed, the Serveo road's too, where the road has a server (ssh-j.com where podssh's list of services names it, or PODSSH_SSH_J) \
     and podssh holds the node's key: --node-key, else the key that the net names for NAME, else the key that \
     the pins of NAME hold from an earlier session. The node's name there comes from that key, as the node \
     derives it. Each link is SSH to the server on port 22, directly or through HTTPS_PROXY's CONNECT; where \
     that dial fails, the forwarders that the binary names carry it, as when no relay host answers \
     (PODSSH_FORWARDER_FALLBACK=no keeps them out); then a channel to the node's name, as ssh -J takes it, under \
     the resumable layer and the end-to-end channel, which checks the node's key, so --no-e2e leaves the road \
     out. Before its first link, a line says that the server, a third party that nobody vouches for, carries \
     the session over SSH that it ends, and that the end-to-end channel keeps its bytes; -v names the server's \
     host key and the name. podssh ping never measures it. PODSSH_SSH_J=no or PODSSH_LAST_RESORT=no turns the \
     road off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, after Serveo's, which follow Pinggy's.
    #[test]
    fn the_notes_of_the_ssh_j_road_follow_serveo_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the ssh-j road");
        assert_eq!(node[at - 1], super::super::notes_serveo::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the ssh-j road");
        assert_eq!(ssh[at - 1], super::super::notes_serveo::SSH);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "port 22", "its key gives", "(78)"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["--node-key", "pins of NAME", "last, before the roads", "PODSSH_FORWARDER_FALLBACK=no", "--no-e2e"]
        {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
