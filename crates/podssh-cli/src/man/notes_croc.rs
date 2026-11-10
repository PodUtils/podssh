//! The notes of croc's relay road (T-694), a last fallback of the
//! operator's ruling Q78: a node of a pair that waits in a room of croc's
//! public relay behind croc-web's WebSocket bridge, and a client that meets
//! it there.

/// The note of `podssh node`, after the transit relay's.
pub(super) const NODE: &str = "A node of the pair's road with the resumable layer and the end-to-end channel \
     (no --plain, no --no-e2e) and a TCP TARGET also waits for the pair's operators at croc's public relays, \
     a last fallback of the operator's ruling Q78: croc-web's WebSocket bridge at the address that podssh's \
     list of services names (wss://getcroc.com/ws, while the list names it; none in this release), or the \
     bridge of PODSSH_CROC (wss://HOST/ws, croc-web of your own before croc relay), through HTTPS_PROXY. The \
     bridge pipes the WebSocket to one of croc's relays, which the pair's secret picks, and the node passes \
     croc's own handshake (a PAKE on the curve SIEC with croc's public key, then the relay's password and a \
     room, in AES-GCM) and waits in the first of the pair's 4 rooms that no link of its own holds; the relay \
     sends it a frame each second while it waits. A client of the pair meets it there, and each proves the \
     pair's secret to the other before the resumable layer, so a peer that knows a room alone, as the relay \
     does, is refused. The rooms and the proof come from the pair's connect token. The node opens its next \
     wait at each meeting, and keeps the sessions of each road with one keeper, so that a session resumes on \
     any; its line names the bridge and, for the public one, says that a volunteer's service that nobody \
     vouches for carries the sessions of this road. croc's relay keeps a room 3 h at most, and a waiting \
     room only while it has fewer than 128: the layer moves a session to a new room, and the node waits \
     again at once. PODSSH_CROC=no or PODSSH_LAST_RESORT=no turns the road off. The bridge and the relay \
     see the room, the sizes and the times; the channel keeps the bytes from them.";

/// The note of `podssh ssh`, after the transit relay's.
pub(super) const SSH: &str = "node://NAME also races croc's relay road of its pair (T-694), after the \
     transit relay's, and only once each road before it failed: the rooms of the pair at croc's relay \
     behind croc-web's bridge, where the node waits, a last fallback of the operator's ruling Q78, before \
     the Pinggy, Serveo and ssh-j roads. The \
     client tries the pair's 4 rooms in order: a room that two members hold sends it to the next, and so \
     does one with no one in it, after 3 s; a client of the same pair that it meets starts the rooms again, \
     once. Before its first link through the public bridge, a line says that croc's relays, a volunteer's \
     service that nobody vouches for, carry the session. Each try of a room is a join, which croc's relay \
     limits for each source (the bridge is one source for all its users), and its answer rate limited is \
     said. PODSSH_CROC=no or PODSSH_LAST_RESORT=no turns it off, a wss:// URL there names your own bridge, \
     and --no-e2e leaves it out; so does a run where a road found the WebSocket upgrade refused on the \
     way, as the bridge is a WebSocket too. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow the transit relay's, in node's and ssh's, and hold
    /// each claim of Q78's third party.
    #[test]
    fn the_notes_of_croc_s_relay_road_follow_the_transit_relay_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of croc's relay road");
        assert!(node[at - 1].contains("magic-wormhole transit relay"), "{}", node[at - 1]);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of croc's relay road");
        assert!(ssh[at - 1].starts_with("node://NAME also races the transit road"), "{}", ssh[at - 1]);
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "PODSSH_CROC=no", "3 h", "SIEC"] {
            assert!(super::NODE.contains(text), "{text}");
        }
        for text in ["nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no", "--no-e2e", "rate limited"] {
            assert!(super::SSH.contains(text), "{text}");
        }
    }
}
