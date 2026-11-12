//! The rows of `--vless` (T-440): VLESS servers that the user runs, in
//! place of the relay, for `ssh` and each command that reaches its server as
//! `ssh` does, for `proxy`, and for `doctor`, which checks each server; and
//! of `--trojan` (T-491), Trojan servers of a file, read as `--vless` reads
//! its own; and of `--tuic` (T-581) and `--hysteria` (T-580), TUIC and Hysteria 2 servers of a file, over QUIC where
//! UDP passes.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each` and the others of `ssh`'s road.
pub const VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through VLESS servers that you run (Xray-core, shoes), in order, in place of the relay: \
     FILE is private, with a vless:// share link on each line, over a WebSocket (type=ws) or XHTTP on HTTP/2 \
     (type=xhttp), which passes where a proxy refuses the upgrade",
    None,
);

/// `proxy`.
pub const PROXY_VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the VLESS servers of FILE, in order, in place of the relay: vless:// share links \
     in a private file",
    None,
);

/// `doctor`.
pub const DOCTOR_VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "also check each VLESS server of FILE, on each mode of XHTTP where its link says auto: the transport that \
     carried it, then one of GitHub's published host keys on github.com port 22 through it",
    None,
);

/// `--trojan` for `ssh`, `cp`, `each` and the others of `ssh`'s road (T-491).
pub const TROJAN: FlagRow = row(
    None,
    "trojan",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through Trojan servers that you run (trojan-gfw, trojan-go, Xray-core), in order, in \
     place of the relay: FILE is private, with a trojan:// share link on each line, in TLS alone (type=tcp) or \
     in a WebSocket over TLS (type=ws)",
    None,
);

/// `--trojan` for `proxy`.
pub const PROXY_TROJAN: FlagRow = row(
    None,
    "trojan",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the Trojan servers of FILE, in order, in place of the relay: trojan:// share links \
     in a private file",
    None,
);

/// `--tuic` for `ssh`, `cp`, `each` and the others of `ssh`'s road (T-581).
pub const TUIC: FlagRow = row(
    None,
    "tuic",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through TUIC servers that you run (sing-box, mihomo, Itsusinn's tuic), in order, in \
     place of the relay, over QUIC where a probe finds that UDP passes: FILE is private, with a tuic:// share link \
     on each line",
    None,
);

/// `--hysteria` for `ssh`, `cp`, `each` and the others of `ssh`'s road (T-580).
pub const HYSTERIA: FlagRow = row(
    None,
    "hysteria",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through Hysteria 2 servers that you run (apernet/hysteria), in order, in place of the \
     relay, where UDP passes: FILE is private, with a hysteria2:// share link on each line; a probe of UDP to \
     each server's port goes first, and with no answer the road ends at once",
    None,
);

/// `--hysteria` for `proxy`.
pub const PROXY_HYSTERIA: FlagRow = row(
    None,
    "hysteria",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the Hysteria 2 servers of FILE, in order, in place of the relay, where UDP passes: \
     hysteria2:// share links in a private file",
    None,
);

/// `doctor`.
pub const DOCTOR_HYSTERIA: FlagRow = row(
    None,
    "hysteria",
    Some("FILE"),
    FlagKind::Supported,
    "also check each Hysteria 2 server of FILE: whether UDP reaches its port, and its round trip, then one of \
     GitHub's published host keys on github.com port 22 through it",
    None,
);

/// `--tuic` for `proxy` (T-581).
pub const PROXY_TUIC: FlagRow = row(
    None,
    "tuic",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the TUIC servers of FILE, in order, in place of the relay, where UDP passes: tuic:// \
     share links in a private file",
    None,
);

/// `--tuic` for `doctor` (T-581).
pub const DOCTOR_TUIC: FlagRow = row(
    None,
    "tuic",
    Some("FILE"),
    FlagKind::Supported,
    "also check each TUIC server of FILE: whether UDP reaches its port, then one of GitHub's published host keys on \
     github.com port 22 through it",
    None,
);
