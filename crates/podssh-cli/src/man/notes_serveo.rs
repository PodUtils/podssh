//! The notes of the Serveo road (T-549), a last fallback of the operator's
//! ruling Q78, before the ssh-j road's: a node behind a private alias at
//! Serveo, and a client that jumps to it.

/// The note of `podssh node NAME TARGET --serveo`.
pub(super) const NODE: &str = "With --serveo, the node serves TARGET over the Serveo road: a private alias at \
     Serveo, which needs no account, at the server that podssh's list of services names, or at the one of \
     PODSSH_SERVEO (HOST[:PORT]); where the list names none, only PODSSH_SERVEO gives the road a server (64 \
     without it). The node's leg is raw SSH to the server on port 443, then 22, through HTTPS_PROXY, as user \
     anonymous, with one remote forward of an alias on port 22, as ssh -R ALIAS:22:localhost:22 asks it; \
     Serveo documents no SSH inside TLS, so a proxy that passes TLS alone leaves the road out. The alias is \
     derived from the node's key, a hash of its fingerprint, so a client that holds the key computes it, and the \
     node's line alias says it. Where another tunnel holds the alias, as Serveo may hold the node's last one a \
     while after an abrupt end, the node takes the next of its series of four, and says so. Each client's \
     channel carries the resumable layer with no TLS of the node's: Serveo sees the alias, the times and the \
     sizes, and the end-to-end channel keeps the bytes. The host key of the server is checked against the one \
     that podssh's list of services names, where it names one; else any key passes, and the line says so. A \
     tunnel that ends is opened again, with the first alias first, and the sessions that the layer keeps go on \
     when their client links again. Anyone who knows the alias may connect to it, and Serveo is a third party \
     that nobody vouches for, so the road needs the end-to-end channel and a door: --allow, or the members of \
     the net held here when the node's key is one; never --plain, --no-e2e, --exit, a udp: TARGET, or \
     --opentunnel, --pinggy, --ssh-j, --iroh or --derp (64). With the pair NAME, or --pair-file, the node serves the \
     pair's road beside it, with one keeper of sessions. A node that would serve the Pinggy road unasked \
     serves this one unasked after the Pinggy road reached no server, or in its place where PODSSH_PINGGY=no, \
     by the operator's ruling Q78, before the ssh-j road and the roads after it, and its lines say so and name the \
     third party. \
     PODSSH_SERVEO=no turns the road off, and so does PODSSH_LAST_RESORT=no, the switch of each last \
     fallback.";

/// The note of the Serveo road of `podssh ssh node://NAME`.
pub(super) const SSH: &str = "node://NAME races the Serveo road too, once each road before it failed and \
     before the ssh-j road and the roads after it, a last fallback of the operator's ruling Q78, where the road has a server (podssh's list of \
     services, or PODSSH_SERVEO) and a key of the node is known: --node-key, else the key that the net names for \
     NAME, else the pins of NAME, which a first session over another road writes. Each link is raw SSH to the \
     server on port 443, then 22, through HTTPS_PROXY, then a direct-tcpip channel to the node's alias, as ssh \
     -J jumps: the alias is a hash of the key's fingerprint, so no name is given or kept, and the aliases of \
     the node's series are tried in their order. The end-to-end channel then checks the node's key, so a \
     stranger that holds the alias is refused, and --no-e2e leaves the road out. Before it, a line says that \
     Serveo, a third party that nobody vouches for, carries the session, and that SSH and the end-to-end \
     channel keep its bytes; -v says which alias it reached. podssh ping node://NAME never measures it. \
     PODSSH_SERVEO=no or PODSSH_LAST_RESORT=no turns the road off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, after Pinggy's.
    #[test]
    fn the_notes_of_the_serveo_road_follow_pinggy_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the Serveo road");
        assert_eq!(node[at - 1], super::super::notes_pinggy::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the Serveo road");
        assert_eq!(ssh[at - 1], super::super::notes_pinggy::SSH);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "derived from the node's key", "series"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["--node-key", "pins of NAME", "stranger that holds the alias is refused", "before the ssh-j road"]
        {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
