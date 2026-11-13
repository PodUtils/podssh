//! The notes of the file hosts' road (T-738), the last of the last
//! fallbacks of the operator's ruling Q78: a node of a pair that polls its
//! door at a public MQTT broker, and a client that knocks there, then each
//! small write of a way a sealed note at the broker, and each larger piece
//! one sealed upload to a public file host, its URL a sealed note there.

/// The note of `podssh node`, after the smee.io road's.
pub(super) const NODE: &str = "In a build with the feature filehost (none of a release yet), a node of the \
     pair's road with the resumable layer and the end-to-end channel (no --plain, no --no-e2e) and a TCP \
     TARGET also waits for the pair's operators through public file hosts, the last of the last fallbacks of \
     the operator's ruling Q78 (T-738), for a proxy that refuses every other road: the hosts of podssh's list \
     of services whose terms let a program upload unasked and that the list has on by default, or those \
     that PODSSH_FILEHOSTS names, over HTTPS \
     by name on 443 through HTTPS_PROXY, with no account. Its door is a topic of the first public MQTT \
     broker of the list (PODSSH_MQTT), whose name comes from the pair's name and connect token, polled each \
     2 s at first and each 60 s at most; a client's hello there names a link. Each write of a way of at \
     most 16 KiB is then a note sealed under the pair's key at a topic of the broker that only the pair can \
     name, with no host (T-773), so the handshakes do not wait for a host; each larger piece, up to 4 MiB, \
     is one upload sealed under that key, at the host's shortest life, and its host, URL and delete token \
     such a note. The reader takes the note, downloads a piece, deletes it where the host lets it, and \
     clears the note. One request of \
     the road at a time, never two connections; uploads at four fifths of a host's published rate, one each \
     30 s where it publishes none, and a host that answers 429 rests while the next takes the piece. Its \
     lines name each host and the broker as third parties that nobody vouches for before their first byte. \
     Slow: for output and files, not for typing. PODSSH_FILEHOSTS=no, PODSSH_LAST_RESORT=no or PODSSH_MQTT=no \
     turns the road off.";

/// The note of `podssh ssh`, after the bore road's.
pub(super) const SSH: &str = "In a build with the feature filehost, node://NAME also races the file hosts' \
     road of its pair (T-738), only once each road before it failed, after every other road, the last of the \
     last fallbacks of the operator's ruling Q78: a hello at the node's door on the public MQTT broker of \
     podssh's list, then each write of a way of at most 16 KiB a sealed note at the broker (T-773), and each \
     larger piece one sealed upload to a public file host (the listed ones whose terms allow it, or those of \
     PODSSH_FILEHOSTS) and its URL a sealed note there, one request at a time. A node polls its door each \
     60 s at most, so the first link may wait that long, until the node takes its hello. Before its first \
     link a line names the broker, and before each host's first upload a line names the host, as third \
     parties that nobody vouches for. PODSSH_FILEHOSTS=no, PODSSH_LAST_RESORT=no or PODSSH_MQTT=no turns it \
     off, and --no-e2e leaves it out. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The node's note follows the smee.io road's, the client's the bore
    /// road's, and both hold each claim of Q78's third party.
    #[test]
    fn the_notes_of_the_file_hosts_road_come_last_of_the_last_fallbacks() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the file hosts' road");
        assert_eq!(node[at - 1], super::super::notes_smee::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the file hosts' road");
        assert_eq!(ssh[at - 1], super::super::notes_bore::SSH);
        let claims = ["Q78", "PODSSH_LAST_RESORT=no", "PODSSH_FILEHOSTS=no", "PODSSH_MQTT=no", "T-738"];
        for text in claims.into_iter().chain(["nobody vouches"]) {
            assert!(super::NODE.contains(text), "{text}");
            assert!(super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("never two connections"));
    }
}
