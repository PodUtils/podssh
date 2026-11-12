//! The notes of `--turn` (T-621, the operator's rulings Q66, Q93 and Q95)
//! for `podssh ssh`, `podssh proxy` and `podssh doctor`, and its file.

pub const SSH: &str = "--turn turns:HOST[:PORT] reaches the first hop through a TURN server that you run \
     (coturn, as a server of calls or chat often has one on 443), in place of the relay, by the operator's \
     rulings Q93 and Q95: a TCP allocation of RFC 6062. podssh opens TLS to HOST (port 443 when none is named), \
     through HTTPS_PROXY when one is set, checked with podssh's trust (--ca-file); asks an allocation for TCP \
     with the credential that the server's 401 asks for; sends Connect with the target's address, which \
     podssh resolves in its own order of resolvers; then opens a second connection to the same server, binds \
     it to the target (ConnectionBind), and carries the session on it, while the first holds the allocation \
     and refreshes it before its lifetime ends. Through a proxy, both are CONNECTs to HOST. turn:HOST[:PORT] \
     (port 3478) has no TLS and goes to this host alone (64). The credential comes from --turn-auth-file FILE \
     (or PODSSH_TURN_AUTH_FILE), never from the URI: see FILES. A server that offers no TCP allocation (442 or \
     508) is refused in those words (69); a credential refused twice (401) and a target that the server's \
     policy refuses (403, as coturn's denied-peer-ip) are refused (77); a target that the server did not \
     reach (447) is said so (69). A proxy that re-terminates TLS stops this road. PODSSH_TURN names the \
     server where the command line names no other road; beside PODSSH_RELAY, PODSSH_FORWARDER, PODSSH_VIA, \
     PODSSH_WSTUNNEL or PODSSH_CHISEL it is refused (78). A run has one road: --relay-host, --relay-failover, \
     --direct, --forwarder, --shadowsocks, --via, --vless, --trojan, --tuic, --hysteria, --wstunnel, --chisel, \
     -4, -6, and a destination with a road of its own cannot go with it (64). The host key of SSH protects the \
     session, as on each road: the server sees the target's address and SSH's encrypted bytes.";

pub const PROXY: &str = "podssh proxy --turn turns:HOST[:PORT] carries the pipe through a TURN server's TCP \
     allocation, with no relay, as podssh ssh does (see its notes); PODSSH_TURN names it too. The bytes go as \
     they are on the second connection, so the end of stdin is its half-close: the target's bytes come until it \
     closes.";

pub const DOCTOR: &str = "With --turn turns:HOST[:PORT] and --turn-auth-file FILE, the section turn gives a \
     line for that TURN server, after the roads over TCP that the run names: its software where it says it, \
     the allocation's relayed address, lifetime and time, and the time of Connect and ConnectionBind, then a \
     session to github.com port 22 through it, whose host key must be one that GitHub publishes. Where TLS \
     fails beside HTTPS_PROXY, the line says that a proxy that re-terminates TLS stops this road.";

/// The file of `--turn-auth-file` in FILES.
pub fn file() -> (Vec<String>, String) {
    (
        vec!["the file of --turn-auth-file".to_string()],
        "The credential of the TURN server of --turn: one line, USER:PASSWORD, split at its first colon (the \
         password may hold colons), or auth-secret SECRET, the static-auth-secret of a coturn of use-auth-secret, \
         from which podssh makes a user and a password of a day, as coturn's REST API makes them. # starts a \
         comment. podssh reads it only as a regular file of yours that others cannot read (on Windows, as its \
         access list says), as a pair file; else, and for a line that cannot be read, the run is refused (78), \
         by the line's number and never its text. podssh never writes it."
            .to_string(),
    )
}
