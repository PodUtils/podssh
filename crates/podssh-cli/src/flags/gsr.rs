//! The flag rows of the GSRN road (T-707): `node`'s road at the relay of
//! gsocket, where two ends that share a secret meet, and `ssh`'s secret file
//! of a node's race. A build with the feature `gsr` alone; another build
//! refuses each of them (70).

use super::{row, FlagKind, FlagRow};

/// `node --gsr`.
#[rustfmt::skip]
pub const NODE_GSR: FlagRow = row(None, "gsr", None, FlagKind::Supported,
    "serve TARGET over the GSRN road, the relay of gsocket with no account (where podssh's list of services names it): one TCP connection to the relay's port 443, directly or through the proxy's CONNECT, at the address that a shared secret gives, from the private file that the flag of the secret's file, or env PODSSH_GSR_SECRET_FILE, names; a client with the same secret races the road last; TLS with SRP of that secret keeps the bytes from the relay, a third party that nobody vouches for; the road alone, with no pair's road beside it; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door; a build with the feature gsr", None);

/// `node --gsr-secret-file FILE`.
#[rustfmt::skip]
pub const NODE_GSR_SECRET_FILE: FlagRow = row(None, "gsr-secret-file", Some("FILE"), FlagKind::Supported,
    "with --gsr: the shared secret, the first line of FILE, a private file of yours, never argv (default: env PODSSH_GSR_SECRET_FILE); a build with the feature gsr", None);

/// `ssh node://NAME --gsr-secret-file FILE`.
#[rustfmt::skip]
pub const SSH_GSR_SECRET_FILE: FlagRow = row(None, "gsr-secret-file", Some("FILE"), FlagKind::Supported,
    "node://NAME: race the GSRN road last, to the node that serves it with the secret of FILE, a private file of yours (default: env PODSSH_GSR_SECRET_FILE); never with --no-e2e; a build with the feature gsr", None);
