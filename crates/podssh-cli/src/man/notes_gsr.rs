//! The notes of the GSRN road (T-707), the relay of gsocket by a shared
//! secret: a node that waits there, a client of `node://NAME` that races it
//! last, doctor's lines, its variable and its secret file. Only a build
//! with the feature `gsr` has the road.

/// The note of `podssh node NAME TARGET --gsr`.
pub(super) const NODE: &str = "In a build with the feature gsr, --gsr serves TARGET over the GSRN road, the \
     relay of gsocket (hackerschoice's Global Socket Relay Network, where podssh's list of services names \
     it), with no account and no token: the node and its clients share one secret, the first line of the \
     private file of --gsr-secret-file or PODSSH_GSR_SECRET_FILE, never argv. The secret gives an address \
     and a shard of the relay; the node keeps one registration there, by one TCP connection to port 443, \
     directly or through HTTPS_PROXY's CONNECT, with a ping each 5 s, under the 15 s at which a proxy was \
     seen to cut an idle tunnel; each client that connects with the same secret is paired with it, and the \
     node registers again at once. TLS with SRP of the secret (OpenSSL, built in and linked static, as \
     rustls has no SRP) keeps the bytes from the relay; the resumable layer and the end-to-end channel run \
     above it, as on each road. Whoever holds the secret reaches the door, so the road needs one: --allow, \
     or the members of the net held here when the node's key is one; never --plain, --no-e2e, --exit, a \
     udp: TARGET, --spares or another road's flag (64). A first registration that fails within 10 s ends \
     the node (69) in the relay's words; a later one is made again after a pause that grows to 30 s. A \
     line names the relay's host and its party as a third party that nobody vouches for. --gsr-secret-file \
     without --gsr is 64; a secret file that cannot be used, or a secret longer than the relay takes (32 \
     bytes), refused (78), in words that never hold it. A build without the feature refuses --gsr and \
     --gsr-secret-file (70).";

/// The note of `podssh ssh node://NAME` with the road's secret.
pub(super) const SSH: &str = "In a build with the feature gsr, node://NAME with --gsr-secret-file FILE or \
     PODSSH_GSR_SECRET_FILE also races the GSRN road, last, once each road before it failed, and before \
     the file hosts' road: a connection to the relay of gsocket at the shard that the secret gives, \
     directly or through HTTPS_PROXY's CONNECT, a CONNECT to the secret's address, and TLS with SRP of the \
     secret with the node of podssh node --gsr; it needs no pair here. The end-to-end channel checks the \
     node's key by the pins of NAME, or --node-key, and the resumable layer resumes a session on a new \
     pairing. A line names the relay as a third party before the first link. Never with --no-e2e; a file \
     that cannot be used is refused (78) before anything connects, and a build without the feature refuses \
     --gsr-secret-file (70) and passes the variable over.";

/// The note of `podssh doctor`.
pub(super) const DOCTOR: &str = "In a build with the feature gsr, the section gsr says whether TLS with SRP \
     builds on both sides (gsr tls, OpenSSL's version), with no connection. Once PODSSH_GSR_SECRET_FILE \
     names the road's secret, it makes one round trip of the control protocol with the relay at the shard \
     of that secret, by a secret that nobody holds, so that no node is disturbed (gsr, its time); with \
     --full, it holds such a registration with the relay's pings alone for 20 s (gsr idle), which says \
     whether a proxy on the way cuts a quiet tunnel before the road's keepalive. With no secret named, no \
     byte goes to the relay.";

/// The variable of the road.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[(
    &["PODSSH_GSR_SECRET_FILE"],
    "The file of the GSRN road's shared secret (T-707), as --gsr-secret-file, which wins: podssh node --gsr \
      serves the road with it, podssh ssh node://NAME races the road last with it, and podssh doctor asks \
      the relay at its shard (see FILES). Unset or empty: no secret. A build with the feature gsr; another \
      build passes it over.",
)];

/// The secret file in FILES.
pub(super) fn file() -> (Vec<String>, String) {
    (
        vec!["the file of --gsr-secret-file and PODSSH_GSR_SECRET_FILE".to_string()],
        "The shared secret of the GSRN road: its first line, without the line end, as gs-netcat -k reads a \
         key file; any later line must be blank. At most 32 bytes, the relay's limit. podssh reads it only \
         as a regular file of yours that others cannot read (on Windows, as its access list says); else, and \
         for a file with no secret, more than one, or a control character, the run is refused (78), in words \
         that never hold the secret. It never goes to argv, a line or the relay: the relay sees the address \
         and the shard that it gives. podssh never writes it."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_notes_of_the_gsrn_road_name_its_feature_its_variable_and_its_refusals() {
        for text in [super::NODE, super::SSH, super::DOCTOR] {
            assert!(text.contains("feature gsr"), "{text}");
        }
        for text in ["PODSSH_GSR_SECRET_FILE", "--gsr-secret-file", "(70)", "(78)", "--no-e2e"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::DOCTOR.contains("PODSSH_GSR_SECRET_FILE"));
    }
}
