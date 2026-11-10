//! The notes of the localtunnel road (T-568), the last fallback of the
//! operator's ruling Q78, after the ssh-j road's: a node behind localtunnel's
//! public server under a name that its key gives, and a client that derives
//! the name and opens a WebSocket to it.

/// The note of `podssh node NAME [TARGET] --localtunnel`.
pub(super) const NODE: &str = "With --localtunnel, the node serves TARGET over the localtunnel road: \
     localtunnel's public server, with no account, where podssh's list of services names it, or the server of \
     PODSSH_LOCALTUNNEL (an https:// URL, or http:// on this host's loopback); with neither, --localtunnel is a \
     configuration error (78). The node asks the server over HTTPS, through HTTPS_PROXY, for a tunnel under a \
     name that its key gives (podssh-, then 16 hex digits), then keeps the TCP connections that the server \
     names, up to 10, to a port that the server's system chose, directly or through HTTPS_PROXY's CONNECT: a \
     proxy that lets CONNECT reach port 443 alone refuses that port, so the node needs an egress that reaches \
     it, while its clients need port 443 alone. A connection that ends is opened again at once; three refused \
     dials in a row mean the server forgot the tunnel, and the node asks for it again, with a wait that doubles \
     from 1 s to 60 s. The tunnel's URL is the one line on stdout. Each visitor's WebSocket is a link of the \
     resumable layer, with the end-to-end channel above it; with --relay, the relay role of podssh relay serve \
     answers its own paths on the same connections, as behind --quick-tunnel, minting for the node's door unless \
     --mint says otherwise, and TARGET may be left out; its relay host is the URL. The server ends the visitors' \
     TLS: it sees the times, the sizes and the layer's bytes, which the end-to-end channel keeps from it; and \
     nothing proves who connects to a tunnel's port there, so a stranger may serve its visitors, whom the \
     channel refuses. Where a stranger holds the name first, the server gives another, which the node says; a \
     client that derives the name then reaches the stranger, and is refused. The road needs the end-to-end \
     channel and a door: --allow, or the members of the net held here when the node's key is one; never \
     --plain, --no-e2e, --exit, a udp: TARGET, or another road's flag (64). The road is served alone: a pair of \
     NAME is not served beside it, and a line says so. A node that would serve the OpenTunnel road, the Pinggy \
     road, the Serveo road or the ssh-j road unasked serves this one, the last of all, when none of them reached \
     a service, or when each is off or has no server, by the operator's ruling Q78, and its lines say so and \
     name the third party, which nobody vouches for. PODSSH_LOCALTUNNEL=no turns the road off, and so does \
     PODSSH_LAST_RESORT=no, the switch of each last fallback.";

/// The note of `podssh ssh node://NAME` on the localtunnel road.
pub(super) const SSH: &str = "node://NAME races the localtunnel road too, last of all, once each road before \
     it failed, the ssh-j road's too, where the road has a server (localtunnel's where podssh's list of services \
     names it, or PODSSH_LOCALTUNNEL) and podssh holds the node's key: --node-key, else the key that the net \
     names for NAME, else the key that the pins of NAME hold from an earlier session. The node's name there \
     comes from that key, as the node derives it. Each link is TLS to that name on port 443 through \
     HTTPS_PROXY, checked by this host's roots for the hosted server, then a WebSocket with the header \
     Bypass-Tunnel-Reminder, which passes the server's page for browsers (a 511, which the line names), under \
     the resumable layer and the end-to-end channel, which checks the node's key, so --no-e2e leaves the road \
     out. Before its first link, a line says that the server, a third party that nobody vouches for, carries \
     the session and ends its TLS, and that the end-to-end channel keeps its bytes. A node with --relay is a \
     relay host too: --relay-host with its URL. podssh ping never measures the road. PODSSH_LOCALTUNNEL=no or \
     PODSSH_LAST_RESORT=no turns it off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, after the ssh-j road's.
    #[test]
    fn the_notes_of_the_localtunnel_road_follow_the_ssh_j_road_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the localtunnel road");
        assert_eq!(node[at - 1], super::super::notes_sshj::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the localtunnel road");
        assert_eq!(ssh[at - 1], super::super::notes_sshj::SSH);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "port 443 alone", "its key gives", "(78)"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["--node-key", "pins of NAME", "last of all", "Bypass-Tunnel-Reminder", "--no-e2e"] {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
