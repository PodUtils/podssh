//! The notes of `--tuic` (T-581) for `podssh ssh`, apart from the others so
//! that each file stays short.

pub const SSH_TUIC: &str = "--tuic FILE reaches the first hop through TUIC servers that you run (sing-box, \
     mihomo, shoes, Itsusinn's tuic), in place of the relay, over QUIC where UDP passes: TUIC version 5, a server \
     that takes a user's UUID and a token of its password, then the target, and dials it. FILE must be yours and \
     closed to others (chmod 600), as a pair file is: each line is a share link as panels and clients give it, \
     tuic://UUID:PASSWORD@HOST:PORT, then ?sni= (or peer=) and alpn= (a comma list; h3 when none), joined by &, \
     and #TAG; # starts a comment. congestion_control, udp_relay_mode, disable_sni and reduce_rtt pass: the \
     first is the sender's own and no server reads it, and this road carries no UDP of its own. A certificate \
     that is not checked (allow_insecure), a version other than 5, and a line that cannot be read are refused \
     (78), the line by its number and never its text. QUIC is UDP, which no HTTP proxy carries, so the road goes \
     beside HTTPS_PROXY, and only where a probe found that UDP reaches the server: one QUIC packet of a reserved \
     version, which a server of QUIC answers at once; with no answer within 1 s the server is not tried, and \
     the line says that UDP does not pass. Then TLS 1.3 inside QUIC, checked for sni (else HOST) with podssh's \
     trust (--ca-file); the token is 32 bytes of TLS's keying material exporter, the UUID its label and the \
     password its context, so neither crosses; and a heartbeat each 10 s while the session lives. TUIC has no \
     answer: the servers are tried in the order of the file, and each waits up to 10 s for the target's version \
     line. A server that closes the connection did not take the UUID or the password, and its words are said \
     (ssh 255, as for each first hop that it does not reach); one that ends the stream with no byte could not \
     reach the target, or its rules refuse it (Itsusinn's tuic refuses a loopback or private target unless its \
     experimental drop_loopback and drop_private are off); each gives way to the next, and -v says the address \
     that QUIC reached. The host key of SSH protects the session, as on each road: the server sees the \
     target's name and SSH's encrypted bytes. A run has one road: --relay-host, --relay-failover, --direct, \
     --forwarder, --shadowsocks, --via, --vless, --trojan, --wstunnel, --chisel, -4, -6, and a destination with a \
     road of its own cannot go with it (64).";
