//! The rows of the DNS road's lines in `doctor` (T-875): `--dns-zone`, which
//! asks a resolver whether a TXT query for a zone of the user's own gets
//! through, and `--dns-server`, the resolver that it asks. Nothing is sent
//! without `--dns-zone` (the owner's ruling Q107).

use super::{row, FlagKind, FlagRow};

/// `doctor`.
pub const DOCTOR_DNS_ZONE: FlagRow = row(
    None,
    "dns-zone",
    Some("ZONE"),
    FlagKind::Supported,
    "also ask a resolver whether a TXT query for a random name under ZONE, a zone of your own, gets through, as the \
     DNS road of --carrier dns:FILE needs: after a probe that UDP opens, one query with EDNS0 and one with none, 3 s \
     each; each line gives the RCODE, the time, the size, TC, the OPT record and any address in the answer",
    None,
);

/// `doctor`.
pub const DOCTOR_DNS_SERVER: FlagRow = row(
    None,
    "dns-server",
    Some("ADDR"),
    FlagKind::Supported,
    "the resolver that --dns-zone asks: IP, IP:PORT or [IPv6]:PORT (default: the first nameserver of \
     /etc/resolv.conf)",
    None,
);
