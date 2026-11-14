//! The flag rows of `funnel` (T-180): a local HTTP service at a public
//! `https://` name, through a quick tunnel that podssh makes itself, or
//! through OpenTunnel, whose TLS ends at this host (T-532).

use super::{row, FlagKind, FlagRow};

/// `funnel`.
#[rustfmt::skip]
pub const FUNNEL_FLAGS: &[FlagRow] = &[
    row(None, "tunnel-token-file", Some("FILE"), FlagKind::Supported,
        "a named tunnel of your own Cloudflare account, by the token in FILE, at the names that the account routes to it, in place of a new NAME.trycloudflare.com; the token goes in no line", None),
    row(None, "warp", None, FlagKind::Supported,
        "reach Cloudflare's edge inside WARP's tunnel first, for a host whose way out does not reach port 7844 (a build with WARP's road)", None),
    row(None, "opentunnel", None, FlagKind::Supported,
        "publish through OpenTunnel, a blind TLS tunnel with no account (opentunnel.xyz, or the service of env PODSSH_OPENTUNNEL), in place of a quick tunnel: TLS ends at this host, with the tunnel's own certificate, so OpenTunnel sees the names, the times and the sizes, never the traffic; one tunnel for this host's funnels, kept in the cache, at https://ID.opentunnel.xyz/; a funnel that the quick tunnel cannot carry takes it unasked (PODSSH_OPENTUNNEL=no turns that off); not with --tunnel-token-file or --warp", None),
];
