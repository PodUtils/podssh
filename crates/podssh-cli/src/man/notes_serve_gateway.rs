//! The note of `podssh serve --gateway` (T-836): the route table, the login
//! upstream by a certificate of the route's CA, and what is carried.

pub const GATEWAY: &str = "--gateway FILE makes serve a gateway in front of private hosts. The login name picks a \
     route of FILE, a block that starts with route PATTERN (* and ?, case-sensitive) and gives on its own lines: \
     upstream HOST:PORT (22 with no port; [IPv6]:PORT), host-key TYPE BASE64, the upstream's key, which serve pins; \
     principal NAME, the user that serve logs in as there; ca-key FILE, a private key with no passphrase, mode \
     0600, beside FILE when its path is relative; one key TYPE BASE64 line for each key that may take the route; \
     and source-address LIST where the upstream must see the gateway's address. The first route whose pattern \
     matches decides; a key that it does not list is refused, and no later route is tried. A name that no route \
     matches is refused: nothing maps to none. A key that is only offered never causes a dial. Once the client has \
     signed with a key of the route, serve makes a fresh key, signs a user certificate of it with the route's CA \
     for the principal alone, valid from 60 s before now to 30 s after, with permit-pty and \
     permit-port-forwarding and nothing else, and logs in at the upstream within 20 s. Its key id is \
     podssh-gateway route=PATTERN user=NAME key=SHA256:..., which the upstream's log names. The upstream must \
     trust the CA: TrustedUserCAKeys of a stock sshd, with the principal allowed for that user. An upstream whose \
     host key is not the pinned one, or that refuses the certificate, refuses the login, and serve's stderr says \
     why. Then each session (pty, shell, exec, subsystem, env, window changes, signals, the exit status) and each \
     forward of -L, -D and -W is carried to the upstream, which answers it; --accept-env and --no-forwarding hold \
     at the gateway first. X11, agent forwarding and -R are refused. When the upstream's connection ends, so does \
     the client's. SIGHUP reads FILE again; a file that does not read keeps the routes before. No private key of a \
     user reaches the gateway; a copy of a route's CA key mints logins for that route's principal until the \
     upstream stops trusting it. A FILE that others may write, that does not read, or that holds no route, and a \
     ca-key that others may read, refuse the start (78), with the file and its line. --gateway with a flag of \
     serve's own sessions (--authorized-key, --authorized-keys, --shell, --pty, --motd, --shell-integration, \
     --share, --keep-lease, --totp, --publish-remote, --remote-listen, --revoke-ends-sessions) is a usage error \
     (64).";
