//! The variables of the TURN road (T-621), and of the file hosts' carrier
//! (T-738), apart from `roads.rs` for its length.

/// `PODSSH_TURN` and its credential file.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_TURN"],
        "The TURN server of podssh ssh, of each command that reaches its server as podssh ssh does, and of podssh \
      proxy, as --turn: turns:HOST[:PORT] (RFC 7065; port 443 when none is named), in place of the relay. The \
      flag wins, and so does each other road's flag; beside PODSSH_RELAY, PODSSH_FORWARDER, PODSSH_VIA, \
      PODSSH_WSTUNNEL or PODSSH_CHISEL, or with a URI that cannot be read, it is a configuration error (78). An \
      empty value is no value.",
    ),
    (
        &["PODSSH_TURN_AUTH_FILE"],
        "The credential file of the server of --turn or PODSSH_TURN, as --turn-auth-file, which wins: a private \
      file of USER:PASSWORD, or auth-secret SECRET (see FILES).",
    ),
    (
        &["PODSSH_FILEHOSTS"],
        "The file hosts' carrier of the resumable layer (T-738), the last of the last fallbacks of the operator's \
      ruling Q78, in a build of podssh-relay with its feature filehost alone; no binary of a release carries it \
      yet: no turns it off; yes, or unset, takes each host of podssh's list of services in its order; a list of \
      the services' ids takes those alone, and an id that the list does not hold is a configuration error (78). \
      PODSSH_LAST_RESORT=no turns it off too.",
    ),
];
