//! The note of `podssh serve --gateway` (T-836): the route table, the login
//! upstream by a certificate of the route's CA, and what is carried; and
//! the routes of the net's signed document, `--gateway net:NAME` (T-902).

pub const GATEWAY_NET: &str = "--gateway net:NAME takes the routes of the gateway NAME from the net's signed \
     document that this host holds (see podssh net). Its owner signs them with podssh net gateway set NAME FILE. \
     FILE holds the blocks of a route file, but each ca-key is the CA's public key, TYPE BASE64. The CA's private key \
     never leaves the gateway's host: name it with --gateway-ca FILE, repeated for each CA. A route whose CA is none \
     of them is refused, with one line; the other routes are taken. With --net-url URL and --net-owner KEY, serve \
     fetches the document as podssh node does. It fetches nothing at the start while the copy from URL is younger \
     than --net-ttl. So a ProxyCommand's serve sends one GET each TTL, however many clients come. A fetch or a \
     document that fails, a bad signature among them, keeps the routes in force, with one line. A newer serial that \
     reads takes their place at the next look, each 5 s, or at SIGHUP. So does a section that the owner removed: \
     nobody passes by it then. A section that this podssh does not read lets nobody in by it either. A document past \
     its end, or a copy past --net-stale, refuses each login until a newer one comes. These refuse the start: no \
     --gateway-ca (64), or a --gateway-ca, --net-url, --net-owner, --net-ttl or --net-stale with no net:NAME (64). \
     So do no document, no route taken, or a document past its end (78). A file whose name begins with net: is \
     given as ./net:NAME.";

pub const GATEWAY: &str = "--gateway FILE makes serve a gateway in front of private hosts. The login name picks a \
     route of FILE, a block that starts with route PATTERN (* and ?, case-sensitive) and gives on its own lines: \
     upstream HOST:PORT (22 with no port; [IPv6]:PORT), host-key TYPE BASE64, the upstream's key, which serve pins; \
     principal NAME, the user that serve logs in as there; ca-key FILE, a private key with no passphrase, mode \
     0600, beside FILE when its path is relative; one key TYPE BASE64 line for each key that may take the route; \
     and source-address LIST where the upstream must see the gateway's address. The first route whose pattern \
     matches decides; a key that it does not list is refused, and no later route is tried. A name that no route \
     matches is refused: nothing maps to none. A key that is only offered never causes a dial. After the client \
     signs with a key of the route, serve makes a fresh key and a user certificate of it by the route's CA. The \
     certificate names the principal alone and is valid from 60 s before now to 30 s after. It permits a pty \
     and port forwarding, nothing else. serve logs in at the upstream with it within 20 s. Its key id is \
     podssh-gateway route=PATTERN user=NAME key=SHA256:..., which the upstream's log names. The upstream must \
     trust the CA: TrustedUserCAKeys of a stock sshd, with the principal allowed for that user. An upstream whose \
     host key is not the pinned one, or that refuses the certificate, refuses the login, and serve's stderr says \
     why. Then each session is carried to the upstream, which answers it: pty, shell, exec, subsystem, env, window \
     changes, signals and the exit status. So is each forward of -L, -D and -W; --accept-env and --no-forwarding hold \
     at the gateway first. X11, agent forwarding and -R are refused. When the upstream's connection ends, so does \
     the client's. SIGHUP reads FILE again; a file that does not read keeps the routes before. No private key of a \
     user reaches the gateway; a copy of a route's CA key mints logins for that route's principal until the \
     upstream stops trusting it. These refuse the start (78), with the file and its line: a FILE that others may write, that does not \
     read, or that holds no route, and a ca-key that others may read. --gateway with a flag of \
     serve's own sessions (--authorized-key, --authorized-keys, --shell, --pty, --motd, --shell-integration, \
     --share, --keep-lease, --totp, --publish-remote, --remote-listen, --revoke-ends-sessions) is a usage error \
     (64).";
