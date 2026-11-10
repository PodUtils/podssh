//! The notes of the Pinggy road (T-548), a last fallback of the operator's
//! ruling Q78: a node behind a TLS tunnel of Pinggy's free tier, and a
//! client that dials its name.

/// The note of `podssh node NAME TARGET --pinggy`.
pub(super) const NODE: &str = "With --pinggy, the node serves TARGET over the Pinggy road: a TLS tunnel of \
     Pinggy's free tier, which needs no account, or of the server of PODSSH_PINGGY (HOST[:PORT]). The node's leg \
     is SSH to Pinggy's server on port 443, through HTTPS_PROXY, as user tls, with one remote forward: raw SSH \
     first; where that fails before SSH's version line, as behind a proxy that passes TLS alone, SSH inside TLS, \
     which the trust of --ca-file, SSL_CERT_FILE or podssh's roots verifies, as for a relay host; a line says \
     which way carries. Pinggy gives the tunnel a name, which the node reads from Pinggy's list of the tunnel's \
     addresses, or from the session's text, and says in its line name, with the pin of its TLS key \
     (SHA256:...) and the command of a client (--pinggy-name NAME#PIN), and keeps under NAME in the cache \
     (pinggy-NAME.name). Pinggy routes each visitor's TLS by its name and never ends it: TLS ends at the node, \
     with a certificate of its own key, which no CA signs, so Pinggy sees the name, the times and the sizes, \
     never the bytes. The node keeps that key in a private file beside its own key (KEY.pinggy-tls.pem), so the \
     pin stays across its names and its starts; with --ephemeral-key, or a file that cannot be used, the key is \
     for the run, and the line says so. The host key of Pinggy's server is checked against the one that \
     podssh's list of services names, where it names one; else any key passes, and the line says so. A free \
     tunnel ends at 60 minutes: the node opens the next, which has a new name, and says it; the sessions that \
     the layer keeps go on when their client dials the new name. In a build with the iroh road, the node puts \
     each tunnel's address (NAME#PIN) in its record of pkarr, signed by its key, at the server of pkarr that \
     the iroh road names, in the place of the last, and its line says so; a client whose net names \
     the node by its key finds the new name there with no --pinggy-name. Each visitor's end has a line, with why it \
     ended and its bytes each way; PODSSH_PINGGY_TRACE=1 adds one each 5 s while it lives. Anyone may connect to a tunnel's name, and \
     Pinggy is a third party that nobody vouches for, so the road needs the end-to-end channel and a door: \
     --allow, or the members of the net held here when the node's key is one; never --plain, --no-e2e, --exit, \
     a udp: TARGET, or --opentunnel, --iroh or --derp (64). With the pair NAME, or --pair-file, the node serves \
     the pair's road beside it, with one keeper of sessions. A node with no pair, a door, the DERP road turned \
     off (PODSSH_DERP=no), and the OpenTunnel road turned off (PODSSH_OPENTUNNEL=no) or with no service \
     reached, serves the road unasked, the last, by the operator's ruling Q78, and its lines say so and name the \
     third party. PODSSH_PINGGY=no turns the road off, and so does PODSSH_LAST_RESORT=no, the switch of each \
     last fallback.";

/// The note of `podssh ssh node://NAME --pinggy-name HOST#PIN`.
pub(super) const SSH: &str = "node://NAME with --pinggy-name HOST#PIN races the Pinggy road too, 250 ms after \
     the road before it: HOST is the name that the node's line name says, and PIN the pin of its TLS key that \
     the line says beside it (SHA256:...); a name with no pin is refused (64). Each link is TCP to HOST on port \
     443 through HTTPS_PROXY, then TLS by HOST with no WebSocket upgrade, so a proxy that refuses the upgrade \
     passes it; the node's certificate is its own, which no CA signs, so TLS takes only a certificate of the \
     pinned key, and refuses another with the key it showed: a stranger at the name, or a proxy that ends TLS. \
     The end-to-end channel then checks the node's own key by the pins of NAME, or --node-key, so --no-e2e \
     leaves the road out (64 with --pinggy-name). The address is kept under NAME in the cache \
     (pinggy-NAME.name). A run that gives none dials the address of the node's record of pkarr, where the net \
     names NAME by its key and the record is asked (the node puts each tunnel's there), else the one kept, last, \
     once each road before it failed, the last fallback of the operator's ruling Q78; the record is signed by \
     the node's key, so its pin is the node's word, and -v says where the address came from. Before it, a line says that Pinggy, a third party that nobody \
     vouches for, carries the session, and that SSH and the end-to-end channel keep its bytes. A free tunnel's \
     name changes each hour, and its pin does not: the record names the new one, else give the new name that \
     the node says, with the same pin. \
     PODSSH_PINGGY=no or PODSSH_LAST_RESORT=no turns the road off.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes stand in node's and ssh's, beside OpenTunnel's.
    #[test]
    fn the_notes_of_the_pinggy_road_follow_opentunnel_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the Pinggy road");
        assert!(node[at - 1].starts_with("With --opentunnel"), "{}", node[at - 1]);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the Pinggy road");
        assert!(ssh[at - 1].starts_with("node://NAME with --opentunnel-name"), "{}", ssh[at - 1]);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "60 minutes", "raw SSH", "pin"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        assert!(super::NODE.contains("record of pkarr"), "the node's record names its address");
        for text in ["HOST#PIN", "only a certificate of the pinned key", "refused (64)", "record of pkarr"] {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
