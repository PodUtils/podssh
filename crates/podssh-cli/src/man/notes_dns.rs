//! The notes of the DNS road (T-875, T-877): doctor's `--dns-zone`, and its
//! bound, the owner's ruling Q107.

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
