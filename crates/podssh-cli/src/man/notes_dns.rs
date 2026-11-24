//! The notes of the DNS road (T-875, T-877): doctor's `--dns-zone`, the
//! node's `--carrier dns:FILE` and its file in FILES, and their bound, the
//! owner's ruling Q107.

/// The note of `podssh doctor --dns-zone ZONE`.
pub(super) const DOCTOR: &str = "With --dns-zone ZONE, the section dns asks whether a resolver passes a TXT query \
     for a zone of your own, as the DNS road needs. The resolver is --dns-server ADDR, else the first nameserver of \
     /etc/resolv.conf. First a UDP socket is opened toward it, which sends nothing. Where the host refuses UDP, the \
     line dns resolver says so, and nothing is sent. Then two queries go, each for a random name under ZONE, so \
     that no cache answers. The first has an OPT record of EDNS0 of 1232 bytes, the second none; each waits 3 s. \
     Each line gives the RCODE, the time, the size and the TC bit. It says whether the OPT record came back, and \
     counts records of another type. NOERROR and NXDOMAIN are ok: the resolver answered for the zone. SERVFAIL, \
     REFUSED, silence and an address in the answer are FAIL. A portal that answers each name itself gives that \
     address. A datagram that answers another query is not taken. No HTTP proxy carries UDP, so the queries go \
     straight to the resolver. Nothing is sent without --dns-zone. The DNS road is a last resort: slow, and plain \
     to the resolver's operator.";

/// The note of `podssh node NAME TARGET --carrier dns:FILE` (T-877).
pub(super) const NODE: &str = "--carrier dns:FILE carries the node's stream in DNS, for a host that reaches a \
     resolver and nothing else. The client's bytes go up in names under a zone of your own; the node's come down \
     in TXT records. The road is pod-link's: an ARQ, and TLS 1.3 with each end's key pinned by the other. The node \
     needs a public address and UDP, and the zone delegated to it by an NS record. It answers at FILE's listen, a \
     listener that you ask for; PODSSH_LISTEN=no refuses it (78). It takes the first client whose key is a peer of \
     FILE, then serves that one stream. The client sends to its resolver: resolver of FILE, else the first \
     nameserver of /etc/resolv.conf. A UDP socket toward it, which sends nothing, comes first. Where the host \
     refuses UDP, the run ends with one line (69), and nothing is sent. At most 20 queries a second and 8 in \
     flight; FILE may lower them, never raise them (78). The road is slow: about 2.6 KB/s up and 18 KB/s down at \
     best. A resolver's operator sees about 2,000 queries an hour while it is idle, and can block the zone. It is \
     a last resort; doctor --dns-zone says whether a resolver passes the zone.";

/// FILE in FILES.
pub(super) fn file() -> (Vec<String>, String) {
    (
        vec!["the file of --carrier dns:FILE".to_string()],
        "The DNS road of a carrier: NAME = VALUE lines, # for a comment. zone, the zone whose names carry the \
         stream. resolver, the client's: system (the default) or IP[:PORT]. listen, the node's IP:PORT of UDP. \
         key-file, this end's key, made private when missing; a line then gives its key for the other end. peer, \
         the other end's key: on a client the node's, on a node each client's, by spaces or commas. \
         queries-per-second (20 at most), in-flight (8 at most), query-timeout and poll-max in seconds, and \
         answer in bytes, 512 to 4096 (1232 by default). A relative path is read beside FILE. A name that is no \
         setting, and a value out of its bound, are refused (78)."
            .to_string(),
    )
}
