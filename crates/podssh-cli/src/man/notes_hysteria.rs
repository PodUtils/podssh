//! The notes of `--hysteria` (T-580, the operator's ruling Q82) for `podssh
//! ssh`, `podssh proxy` and `podssh doctor`, and its file in FILES.

pub const SSH: &str = "--hysteria FILE reaches the first hop through Hysteria 2 servers that you run \
     (apernet/hysteria), in place of the relay, where UDP passes, by the operator's ruling Q82: a server of \
     QUIC that takes a credential in one HTTP/3 request, dials the target named on a stream of its own, and \
     to one who has no credential is a web server. FILE must be yours and closed to others (chmod 600), as a \
     pair file is: each line is a share link as Hysteria's clients give it, hysteria2://AUTH@HOST[:PORT]/ or \
     hy2:// (443 when no port), then ?sni=, pinSHA256=, insecure=, obfs=salamander and obfs-password=, joined \
     by &, and #NAME; # starts a comment. AUTH is the server's password, or USER:PASSWORD for its userpass. \
     TLS 1.3 is checked for sni (else HOST) with podssh's trust (--ca-file), or, with pinSHA256 (64 hex \
     digits, as Hysteria prints them), the server's own certificate alone passes, by the SHA-256 of its DER. \
     obfs=salamander wraps each datagram in Salamander, with its password of 4 bytes or more. insecure=1 with \
     no pinSHA256, several ports (port hopping), obfs=gecko, ech and a realm (hysteria2+realm://) are refused \
     by their names (78), and so is a line that cannot be read, by its number and never its text. No HTTP \
     proxy carries UDP: a server whose host has a proxy of HTTPS_PROXY is not tried (69), and NO_PROXY with \
     its host lets UDP go straight to it. The servers are tried in the order of the file, each after a probe: one QUIC packet of a reserved version to the server's port, sent three times \
     within 1.5 s, which a server of QUIC answers at once. With no answer, the road ends with a line that \
     UDP does not reach the server, and waits for no QUIC handshake. A server that answers the credential \
     with another status than 233 did not take it (proxy exits 77; ssh 255, as for each first hop that it \
     does not reach); one that could not reach the target says so in its words; each gives way to the next. \
     The session's QUIC keeps a keepalive each 10 s and ends after 30 s of silence. The host key of SSH \
     protects the session, as on each road: the server sees the target's name and SSH's encrypted bytes. A \
     run has one road: --relay-host, --relay-failover, --direct, --forwarder, --shadowsocks, --via, --vless, \
     --trojan, --wstunnel, --chisel, -4, -6, and a destination with a road of its own cannot go with it (64).";

pub const PROXY: &str = "podssh proxy --hysteria FILE carries the pipe through the Hysteria 2 servers of FILE, \
     in order, with no relay, where UDP passes, as podssh ssh does (see its notes); the flag wins over \
     PODSSH_CHISEL, PODSSH_WSTUNNEL and PODSSH_VIA. The server answers once it reached the target, so a pipe \
     whose client speaks first waits for no silence. The end of stdin closes the stream's way up, which the \
     server passes on to the target.";

pub const DOCTOR: &str = "With --hysteria FILE, the section hysteria gives a line for each server of FILE, \
     after the roads over TCP that the run names: whether UDP reaches its port, the address that answered \
     the probe and its round trip, and the time of the session through it, then a session to github.com \
     port 22 through it, whose host key must be one that GitHub publishes. Where the probe gets no answer, \
     the line says that UDP does not pass here, with no wait for QUIC; a server whose host has a proxy of \
     HTTPS_PROXY, which carries no UDP, is not tried, and its line says so.";

/// The file of `--hysteria` in FILES.
pub fn file() -> (Vec<String>, String) {
    (
        vec!["the file of --hysteria".to_string()],
        "The Hysteria 2 servers of --hysteria: a hysteria2:// or hy2:// share link on each line (see podssh \
         ssh); # starts a comment. Each link holds the server's credential, and Salamander's password where it \
         names one, so podssh reads it only as a regular file of yours that others cannot read (on Windows, as \
         its access list says), as a pair file; else, and for a line that cannot be read, the run is refused \
         (78), by the line's number, never its text. podssh never writes it."
            .to_string(),
    )
}
