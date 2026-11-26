//! The notes of `podssh serve --listen` (T-124): its addresses, the bind
//! as the probe, the caps, and the stop; the deadline of a login (T-631). Apart from `notes_serve` so that
//! each file stays short; `notes_serve` names these paragraphs.

/// `--listen ADDR`: the addresses, and who can connect.
pub const LISTEN: &str = "podssh serve --listen ADDR is the same server on a listener that you ask for. PORT alone \
     listens on 127.0.0.1. ADDR:PORT takes an address of this host, and [ADDR]:PORT an IPv6 one. The name localhost \
     means 127.0.0.1, and no other name is resolved. \
     unix:PATH is a socket of mode 0600: a client of another user is closed. --listen may be repeated; each address \
     binds at the start, in order. Port 0 lets the system choose, and serve's line names the port. Each connection \
     is served as one of --stdio, with the same keys, host key and flags. On a TCP socket, the client's address meets \
     from= of a key line; on a socket of unix:, no from= matches. --stdio, NAME and --listen are one of the three \
     (64).";

/// The bind is the probe, and its refusal.
pub const BIND: &str = "The bind is the probe: serve makes no other socket to test it. A bind that the host refuses \
     ends the start with 77. Its line names the address, the system's words, and the ways with no listener: \
     cannot listen on 127.0.0.1:2222: Permission denied; this host refuses the listener. Another failure, such as a \
     port in use, ends it with 69. A path that is not a socket is never removed (64). PODSSH_LISTEN=no refuses \
     --listen before any bind (78). Each bind comes before the drop of the capabilities, so a port under 1024 binds \
     where the start holds cap_net_bind_service.";

/// The caps, and the stop.
pub const CAPS: &str = "Each connection takes a place under --max-connections (64 by default) at its accept, before \
     a byte is read. One more gets serve's version line and a disconnect, too many connections, with the cap named. \
     OpenSSH prints it: Received disconnect ... 12: podssh serve: 64 connections at once already. Past 16 such \
     refusals under way, a connection is closed with no word, and one line a second says so. A place comes back when \
     its connection ends. SIGTERM or SIGINT closes each listener, and its socket's file goes. Then each connection \
     stops as under --stdio, and serve exits 0. SIGHUP reads the keys again for each connection. A listener whose \
     accept fails 10 times in a row listens no more; with none left, serve exits 69.";

/// The deadline from the accept, and the cap on those not logged in.
pub const DEADLINE: &str = "Each connection must log in within --login-timeout SECS of its accept (60 by default, 1 \
     to 3600). The time is counted from the accept, not from the last byte: a client that sends a byte now and then \
     ends at the same time. Past it, serve sends a disconnect: podssh serve: no login within 60 s of the connection \
     (--login-timeout). A client that sent no version line yet is closed with no disconnect. Each end is one line of \
     serve's log. A login in time cancels the deadline. --pending-max N (16 by default) caps the connections that \
     have not logged in. One more is refused as past --max-connections, with --pending-max named. A login gives its \
     place back at once.";
