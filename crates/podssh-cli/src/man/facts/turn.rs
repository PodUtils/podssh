//! The variables of the TURN road (T-621), apart from `roads.rs` for its
//! length.

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
];
