//! The notes of `podssh funnel` (T-180, and its OpenTunnel road, T-532),
//! apart from the others so that each file stays short.

pub const FUNNEL: &[&str] = &[
    "podssh funnel TARGET publishes a local HTTP service at a public https:// name, as Tailscale's funnel does, \
     through a quick tunnel that podssh makes itself, with no cloudflared, no relay and no listener: the name is a \
     new NAME.trycloudflare.com for each run, and the one line on stdout once the edge registered the tunnel. TARGET is HOST:PORT or tcp:HOST:PORT, \
     dialed from this host as podssh pipe dials one; unix-connect:PATH, a service on a Unix socket; or exec:CMD, a \
     program started for each request, its stdin the request and its stdout the answer, as inetd starts one. A \
     host whose sandbox refuses a connection to the loopback still serves a socket or a program.",
    "Each visitor's request goes to a new connection of TARGET as HTTP/1.1, with Connection: close, so that the \
     answer ends with the connection: its status and its headers go to the edge, and its body as it comes; a body \
     in chunks is decoded as it comes, as the edge takes a body's bytes alone. A request's body goes to TARGET as \
     it comes too, of any size, with its length, or in chunks where the visitor named none; an answer that TARGET \
     gives before the body's end goes to the visitor at once. An interim answer (100 Continue) is dropped. A \
     WebSocket passes through: TARGET answers its upgrade, and after its 101 the frames pass both ways untouched. \
     podssh reads the heads and never a body. A TARGET that does not answer a request's dial gets the visitor a \
     502 in podssh's words, and a line on stderr.",
    "TLS ends at Cloudflare's edge, so Cloudflare can read each byte of this traffic, and the first lines say so. \
     The name is public: anyone who learns it reaches TARGET, with no key and no allowlist, so publish only what \
     may be public, and stop the funnel with Ctrl-C. For a channel that only your keys open, use the quick \
     tunnel of podssh node NAME TARGET (its notes say how), whose visitors are SSH clients of your net.",
    "--tunnel-token-file FILE serves a named tunnel of your own Cloudflare account in place of a quick tunnel, by \
     the token that the account's dashboard gives for it: the name is then the one that the account routes to \
     the tunnel, which podssh does not know, so stdout stays empty and the first line names the tunnel's id. The \
     token is a credential: podssh reads it from FILE only, and says it in no line. The funnel reaches the edge \
     as the quick tunnel of podssh node does: QUIC on UDP port 7844 where no proxy is set, else HTTP/2 on TCP port \
     7844, directly or through HTTPS_PROXY, and with --warp inside WARP's tunnel first; it keeps two connections, \
     and connects again after a loss with the same name, until Ctrl-C.",
    "--opentunnel publishes through OpenTunnel, a blind TLS tunnel with no account (https://opentunnel.xyz, or \
     the service of PODSSH_OPENTUNNEL), in place of a quick tunnel. Its TLS ends at this host: the funnel makes \
     one tunnel for this host's funnels, with a key that never leaves it and a certificate of the tunnel's own \
     name that the service gets for it, keeps both in the cache, and serves the name https://ID.opentunnel.xyz/, \
     the one line on stdout once its bridge attached, and the same at each run. The first lines say: \"TLS ends \
     at this host; OpenTunnel sees the names, the times and the sizes.\" Each visitor's connection comes over \
     the funnel's bridge, a WebSocket through HTTPS_PROXY, so it leaves a cage of an HTTPS proxy with no WARP. \
     The funnel offers HTTP/1.1 alone; each request goes to TARGET as above, and its answer as TARGET framed it, \
     with Connection: close; a WebSocket passes through. The name is public, as a quick tunnel's is: each \
     visitor who knows it comes in. By the operator's ruling Q76, a funnel with no token file that the quick tunnel cannot carry \
     (no answer of its API, or no road to port 7844 of the edge) takes this road unasked, says why, and tries \
     for 20 s at most; PODSSH_OPENTUNNEL=no turns that off. --opentunnel takes neither --tunnel-token-file nor \
     --warp (64). Two funnels of one host at once share the tunnel's name, which one bridge holds: the second \
     says so, and tries again until the first stops.",
];
