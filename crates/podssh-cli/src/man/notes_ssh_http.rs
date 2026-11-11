//! The notes of the localhost.run road (T-565), the last fallback of the
//! operator's ruling Q78, after the ssh-j road's: a node behind a tunnel of
//! HTTP made by ssh -R, and a client that takes a WebSocket at its name.

/// The note of `podssh node NAME TARGET --localhost-run`.
pub(super) const NODE: &str = "With --localhost-run, the node serves TARGET over the localhost.run road: a \
     tunnel of HTTP made by ssh -R with no account, at localhost.run where podssh's list of services names it, \
     or at the server of PODSSH_LOCALHOST_RUN (HOST[:PORT]); with neither, --localhost-run is a configuration \
     error (78). The node's leg is SSH to the server on port 22, directly or through HTTPS_PROXY's CONNECT, as \
     the user nokey, with the remote forward of port 80, as ssh -R 80:localhost:PORT nokey@localhost.run asks \
     it; the server's line that says tunneled names the tunnel's HTTPS name, which the node says in its line \
     tunnel https://NAME with the command of a client, keeps under NAME in the cache and puts in its record. \
     The service ends each visitor's TLS and sends its HTTP down the tunnel: a WebSocket at / is a link of the \
     resumable layer, under the end-to-end channel, which keeps the bytes from the service; it sees the name, \
     the times and the sizes. A free name changes after a few hours: the node says each new one, and puts it \
     in the record and the cache in the place of the last. With --relay, the relay's forward and reverse roads \
     are served behind the tunnel too, as behind a quick tunnel, and TARGET may be left out; each other path \
     gets 404. Its host key is checked against the one that podssh's list of services names, where it names \
     one; else any key passes, and the line says so. Anyone may visit the name, so the road needs the \
     end-to-end channel and a door: --allow, or the members of the net held here when the node's key is one; \
     never --plain, --no-e2e, --exit, a udp: TARGET, or --opentunnel, --pinggy, --serveo, --ssh-j, \
     --localtunnel, --bore, --iroh, --derp, --quick-tunnel or --frp (64). A tunnel that ends is opened again, with a wait that doubles from 1 \
     s to 60 s, and the sessions that the layer keeps go on over the next. The road is served alone: a pair of \
     NAME is not served beside it, and a line says so. A node that would serve the ssh-j road unasked serves \
     this one, before the localtunnel and bore roads, when it reached no service, or when it is turned off, by the operator's ruling \
     Q78, and its lines say so and name the third party, which nobody vouches for. PODSSH_LOCALHOST_RUN=no \
     turns the road off, and so does PODSSH_LAST_RESORT=no, the switch of each last fallback. With \
     --sandhole, the node serves the same road at Sandhole's public server (demo.sandhole.com.br where podssh's \
     list of services names it, or the server of PODSSH_SANDHOLE): its leg is SSH on port 443, then 22, as the \
     user tunnel with a key made for the login alone, never the node's; the server's line that says Starting \
     HTTPS names a random name under its own, new at each connection. A node that would serve the localhost.run \
     road unasked serves this one after it when it reached no server; PODSSH_SANDHOLE=no turns it off.";

/// The note of `podssh ssh node://NAME` on the localhost.run road.
pub(super) const SSH: &str = "node://NAME with --tunnel-url https://HOST races the localhost.run road too, \
     250 ms after the road before it: a WebSocket at / of HOST, the name that the node prints, on port 443 \
     through HTTPS_PROXY, whose TLS this host's roots verify, under the resumable layer and the end-to-end \
     channel, which checks the node's key, so --no-e2e leaves the road out (64 with --tunnel-url). The name is \
     kept under NAME in the cache; a later run that gives none dials it, or the name of the node's record for a \
     member that the net names by its key, last, once each road before it failed, the ssh-j road's too, and \
     before the localtunnel and bore roads. \
     Before its first link, a line says that localhost.run, a third party that nobody vouches for, carries the \
     session over HTTPS that it ends, and that the end-to-end channel keeps its bytes. A free name changes \
     after a few hours. podssh ping measures it only with --tunnel-url. PODSSH_LOCALHOST_RUN=no or \
     PODSSH_LAST_RESORT=no turns the road off. A name under Sandhole's tunnels' zone is the Sandhole road's: \
     its line names Sandhole, and PODSSH_SANDHOLE=no turns it off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, after the ssh-j road's.
    #[test]
    fn the_notes_of_the_localhost_run_road_follow_the_ssh_j_road_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the localhost.run road");
        assert_eq!(node[at - 1], super::super::notes_sshj::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the localhost.run road");
        assert_eq!(ssh[at - 1], super::super::notes_sshj::SSH);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "nokey", "port 80", "--relay", "(78)"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["--tunnel-url", "WebSocket at /", "last, once each road before it failed", "record", "--no-e2e"] {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
