//! The notes of the bore road (T-569), the last fallback of the operator's
//! ruling Q78, after localtunnel's (T-568): a node at a public TCP port of bore's protocol,
//! at a port that its key gives, and a client that derives the port.

/// The note of `podssh node NAME TARGET --bore`.
pub(super) const NODE: &str = "With --bore, the node serves TARGET over the bore road: bore.pub, a public \
     server of bore's protocol that gives a TCP port with no account, where podssh's list of services names it, \
     or the server of PODSSH_BORE (HOST[:PORT], its control port, 7835 where none is named); with neither, --bore \
     is a configuration error (78). Its control connection is raw TCP to the server's port 7835, directly or \
     through HTTPS_PROXY's CONNECT: no TLS and no HTTP, so a proxy that allows port 443 alone leaves the road \
     out. On it, the node asks a public port that its key gives, the next of a series of four where the server \
     refuses one (another holds it, or it is outside the server's range); its line bore port says HOST:PORT and \
     the command of a client. A client that holds the node's key derives the same ports, so neither says them to \
     the other and no record is needed. Each visitor comes as a Connection on the control connection, which the \
     node takes on a new connection to port 7835 with Accept, then a hello of its key, so that a client passes \
     over a port that another holds. The server sees the times, the sizes and the layer's bytes, which the \
     end-to-end channel keeps from it. Anyone may take any port there, so the road needs the end-to-end channel \
     and a door: --allow, or the members of the net held here when the node's key is one; never --plain, \
     --no-e2e, --exit, a udp: TARGET, or another road's flag (64). \
     bore.pub restarts on purpose and ends a tunnel at 24 hours: a registration that ends is made again, at once \
     after one that lived a minute, else with a wait that grows from 1 s to 30 s, and the sessions that the \
     layer keeps go on over the next; a client that reaches a stranger at a port is refused by the end-to-end \
     channel. The road is served alone: a pair of NAME is not served beside it, and a line says so. A node that \
     would serve the OpenTunnel road, the Pinggy road, the Serveo road, the ssh-j road, the localhost.run road \
     or the localtunnel road unasked serves this one, the last of all, when none of them reached a service, or when each is turned off, by the operator's \
     ruling Q78, and its lines say so and name the third party, which nobody vouches for. PODSSH_BORE=no turns \
     the road off, and so does PODSSH_LAST_RESORT=no, the switch of each last fallback.";

/// The note of `podssh ssh node://NAME` on the bore road.
pub(super) const SSH: &str = "node://NAME races the bore road too, last of all, once each road before it \
     failed, the ssh-j, localhost.run and localtunnel roads' too, where the road has a server (bore.pub where podssh's list of services names \
     it, or PODSSH_BORE) and podssh holds the node's key: --node-key, else the key that the net names for NAME, \
     else the key that the pins of NAME hold from an earlier session. The node's ports come from that key, as \
     the node derives them. Each link is raw TCP to a port of the key, the one that answered last first, \
     directly or through HTTPS_PROXY's CONNECT; where that dial fails, as behind a proxy that allows port 443 \
     alone, the forwarders that the binary names carry it, as when no relay host answers \
     (PODSSH_FORWARDER_FALLBACK=no keeps them out); a port whose first bytes are not the node's hello sends the \
     link to the next. The link runs the resumable layer and the end-to-end channel, which checks the node's \
     key, so --no-e2e leaves the road out. Before its first link, a line says that the server, a third party \
     that nobody vouches for, carries the session over raw TCP, and that the end-to-end channel keeps its \
     bytes; -v names the ports. podssh ping never measures it. PODSSH_BORE=no or PODSSH_LAST_RESORT=no turns \
     the road off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, after localtunnel's, the last before them.
    #[test]
    fn the_notes_of_the_bore_road_follow_localtunnel_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the bore road");
        assert_eq!(node[at - 1], super::super::notes_localtunnel::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the bore road");
        assert_eq!(ssh[at - 1], super::super::notes_localtunnel::SSH);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "7835", "raw TCP", "its key gives", "(78)"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["--node-key", "pins of NAME", "last of all", "PODSSH_FORWARDER_FALLBACK=no", "--no-e2e", "443"] {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
