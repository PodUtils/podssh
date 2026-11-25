//! The notes of grants used once (T-226), and of the bearer in a grant's
//! place (T-834), for `node`, `operator`, `proxy`, `ssh`, `pipe` and
//! `relay`, apart from the others so that each file stays short.

/// The node's door for grants, and its mint.
pub(super) const NODE: &str = "A node lets in an operator with a grant used once, also one whose key no \
     --allow names: an OpenSSH user certificate of the operator's key, which the end-to-end channel carries \
     from it, encrypted, so no relay sees it. Its issuer is the node's own key, or a key of --allow (or a \
     member of the net) for what that key may reach itself. Its principal is node: and the node's \
     fingerprint (node:SHA256:...), with /ROUTE for a route; it has a window, and the critical option \
     once@podssh. Before it dials, the node checks that the channel proved the certificate's key. It checks the \
     issuer's signature, a user certificate, the principal, the window (5 minutes of skew), each critical \
     option, and the serials of --revoked FILE. Then it records the grant as used, in grants-NAME of the cache, \
     synced, and only then lets the session in. A second use of it is thus refused, also after a restart, and a \
     crash between the two spends it. A grant that leaks is worth nothing without its key. \
     The resumable layer carries the session on with no new check. podssh node NAME --grant-to KEY prints \
     one on stdout and serves nothing: the node's key signs it for KEY (ssh-ed25519 BASE64, or its 64 hex \
     digits), for its TARGET or for --grant-route ROUTE. KEY may be a file of the line that podssh keygen -y \
     prints; a private key file is refused (exit 78). --grant-route +exit names the node's exit: its caller \
     goes out to public addresses alone, never to a range of --routes. Port 25, private, loopback and metadata \
     addresses are refused as podssh relay serve refuses them. Its issuer is the node's key, or a member that may \
     go out through the exit itself. It is for --grant-for TIME (1h by default), with a \
     random serial; the operator gives it with podssh operator --grant FILE. An issuer of --allow makes one with \
     OpenSSH: ssh-keygen -s ISSUER -I ID -n node:SHA256:... -O clear -O critical:once@podssh -V +1h KEY.pub. \
     With PODSSH_CACHE_DIR=none no use can be recorded, and each grant is refused. A node with no --allow and no \
     net says that the pair's token alone is its door. A TARGET that is not SSH has no other gate behind it. \
     The same door takes a bearer of an operator's --bearer: a token of 30 s that a key signs for one channel. \
     Its signer is one that may issue a grant, for what that key may reach itself. The node checks the bearer's \
     signer, signature, life (10 s of skew), operator key and channel. It keeps each bearer in memory for its \
     life, and refuses a second use. A bearer copied to another channel is refused: it names the channel's \
     binding. The node's log names the check that refused it.";

/// `operator --grant`.
pub(super) const OPERATOR: &str = "--grant FILE gives a grant used once, KEY-cert.pub of ssh-keygen -s or the line \
     of podssh node --grant-to, for this session: the end-to-end channel carries it to the node once its key was \
     checked, never a relay or a URL. A URL in its place is refused (64), as is --no-e2e beside it. A file that is \
     no Ed25519 certificate is 78. The grant must name this operator's key (client.key, or --client-key); a line \
     says so when it names another, with this key in the form that the issuer signs. A node that refuses the grant \
     (used already, out of its window, or for another key, node or route) is 77. Its reasons are in the node's log. \
     A node of an earlier podssh reads no grant, and ends the session in its handshake. Each grant lets in one \
     session: a run that opens more sends it in the first. \
     --bearer SIGNER gives a bearer in the place of a grant, for a key that no podssh node --allow names. SIGNER is \
     a podssh key file, read and never made. agent is the first Ed25519 key of the SSH agent at SSH_AUTH_SOCK; \
     agent:SHA256:... names one. On Windows the agent is also OpenSSH's pipe, or Pageant. The bearer is made once \
     the node's key was checked, for that channel alone, and lives 30 s. Its signer must be the node's key, a key \
     of the node's podssh node --allow, or a member of its net. A URL, --grant or --no-e2e beside it is refused \
     (64). A key file that cannot be read, or an agent with no such key, is 78. A node that refuses the bearer is \
     77. An agent that does not sign in 20 s is said, and the channel then carries no bearer. Like a grant, it goes \
     in the first session of a run.";

/// `proxy node://NAME --grant`.
pub(super) const PROXY: &str = "node://NAME takes --grant FILE as podssh operator does: a grant used once, in \
     the end-to-end channel of the one session. It takes --bearer SIGNER as podssh operator does too.";

/// `ssh node://NAME --grant`.
pub(super) const SSH: &str =
    "node://NAME with --grant FILE carries a grant used once in the end-to-end channel of the \
     session. The grant is an OpenSSH certificate of this client's key (client.key, or --client-key). A node lets it \
     in once although no line of its allowlist names that key (see podssh node). A URL in its place, and \
     --no-e2e beside it, are refused (64); a destination that is no podssh end is too. --bearer SIGNER carries a \
     bearer in its place, as podssh operator --bearer makes it.";

/// `pipe --grant`.
pub(super) const PIPE: &str = "--grant FILE gives the first session of a node: side a grant used once, as \
     podssh operator --grant takes it; a pipe with no node: side refuses it (64), and a listening side's \
     later clients carry none. --bearer SIGNER is taken the same way, as podssh operator --bearer takes it.";

/// `relay pair --once`.
pub(super) const RELAY: &str = "podssh relay pair NAME --once asks the relay for a pair whose connect token \
     takes one upgrade alone: one operator's session. Its later legs take the tokens of one leg that its node \
     gives, where the node gives them; else the session has no resume. After it the token is refused, also by the \
     status. So a token that leaks from a log after its use is worth nothing. podssh relay serve makes one, and \
     offers it in its /relays.json; a relay that makes none is said so (69), and the pair that it made is stopped. \
     The node's token and the stop token stay as they are; --renew is refused with it (64).";
