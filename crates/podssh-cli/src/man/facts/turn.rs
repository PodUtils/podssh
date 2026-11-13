//! The variables of the TURN road (T-621), and of the file hosts' road
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
        "The file hosts' road of a pair (T-738), the last of the last fallbacks of the operator's ruling Q78, in \
      a build with the feature filehost (none of a release yet): each small write of a link of the resumable \
      layer a sealed note at the public MQTT broker of PODSSH_MQTT, and each larger piece one sealed upload to \
      a public file host of podssh's list of services, its URL a sealed note there, one request at a time (see \
      the notes of node and ssh). no turns it off; yes, \
      or unset, takes the hosts of the list whose terms let a program upload unasked, in the list's order; a \
      list of the services' ids, by commas, takes those alone, in that order (naming a host whose terms ask \
      for its user's consent gives it), and an id that the list does not hold is a configuration error (78). \
      PODSSH_LAST_RESORT=no, or PODSSH_MQTT=no (no board), turns it off too.",
    ),
];
