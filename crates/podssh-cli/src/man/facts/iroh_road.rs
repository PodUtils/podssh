//! The manual's facts of the iroh road, which only a build with the feature
//! `iroh` has: its variables (T-165, T-359, T-350), and its items in THE
//! RELAY, its relays and a node's record of its roads (T-350, T-445).

use super::super::model::Block;
#[cfg(feature = "iroh")]
use super::{item, lit};

/// The variables of the iroh road (T-165), which only a build with the
/// feature `iroh` reads.
#[cfg(feature = "iroh")]
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_IROH_RELAY"],
        "The iroh relays, as --iroh-relay: https://HOST[:PORT], separated by commas, in order. The flag \
          wins; an empty value is no value, and a bad one is a configuration error (78). With neither, the \
          iroh relays that the net's relay members serve on their own hosts come first, then n0's.",
    ),
    (
        &["PODSSH_IROH_UDP"],
        "off: the iroh road takes no direct path, and its relay carries each byte, as where UDP is refused. on: \
          UDP is used once a socket binds, with nothing sent, for a relay that runs no QUIC address discovery. \
          Else UDP is used once a datagram came back: a QUIC address discovery to the home relay within 6 s of \
          the start, before anything is dialled or served; with none, the relay carries each byte. -v says \
          which answer the road took, and at a session's end which path carried it; podssh doctor's line iroh \
          UDP out gives the answer.",
    ),
    (
        &["PODSSH_IROH_QUIC"],
        "The QUIC settings of the iroh road, at each end, and for a measurement of one arm against another: tuned \
          (rtt, window and streams; the default), iroh (iroh's own), or words separated by commas: rtt (an initial \
          round trip of 100 ms, for 333 ms); window (an initial window of 32 packets, for 10); streams (receive \
          windows of 8 MiB a stream and 16 MiB a connection); and one of cubic (iroh's own), bbr or newreno. -v, and \
          a node's lines, say an arm that is not iroh's own. A bad value is a configuration error (78).",
    ),
    (
        &["PODSSH_IROH_PKARR"],
        "The server of pkarr where a node keeps the record of its roads, and where a client asks for it: \
          https://HOST[:PORT][/PATH], or off for none. Unset or empty, it is n0's when the iroh relays are n0's, and \
          none else; a node with no iroh road (--quick-tunnel, the DERP road alone) keeps its record at n0's too. It \
          does so unless this names another or off (see iroh record in THE RELAY). A bad value is a configuration \
          error (78).",
    ),
];

#[cfg(not(feature = "iroh"))]
pub(super) const VARIABLES: &[(&[&str], &str)] = &[];

/// The items of the iroh road in THE RELAY, in a build that has it.
#[cfg(feature = "iroh")]
pub(super) fn blocks() -> Vec<Block> {
    vec![relays(), record()]
}

#[cfg(not(feature = "iroh"))]
pub(super) fn blocks() -> Vec<Block> {
    Vec::new()
}

/// The relays of the iroh road (T-165).
#[cfg(feature = "iroh")]
fn relays() -> Block {
    use pod_iroh::relays;
    item(
        vec![lit("iroh relays")],
        format!(
            "The iroh road (podssh node --iroh, podssh ssh iroh:TICKET) has relays of its own: {}, or those of \
             --iroh-relay or {}, the flag first. podssh asks /ping of each, in order, through the proxy, {} s \
             at most each, and the first that answers is the home relay; a node's ticket names it. A client \
             asks the relay of the ticket first. When none answers, iroh probes them all and takes the one \
             that answers fastest.",
            relays::default_urls().join(", "),
            relays::ENV,
            relays::PING_LIMIT.as_secs()
        ),
    )
}

/// A node's record of its roads at a server of pkarr (T-350, T-445).
#[cfg(feature = "iroh")]
fn record() -> Block {
    use pod_iroh::pkarr;
    item(
        vec![lit("iroh record")],
        format!(
            "A node of the iroh road keeps a record of its roads, signed with its key, at a server of pkarr: \
             {n0} when its relays are n0's, else the one of {env}, and none with {env}=off. The record names its \
             home relay in iroh's own _iroh names, which iroh's tools read. In podssh's _podssh names, which they \
             pass by, it names its DERP home (its ticket, with --derp) and its quick tunnel. It names its Pinggy \
             tunnel (NAME#PIN, with --pinggy) and its OpenTunnel name (with --opentunnel, once its tunnel is \
             ready) there too; no address of the host. The node puts it through the proxy at its start, again when \
             a road comes or moves, and each {minutes} minutes. A Pinggy tunnel's name changes each hour. A node \
             of --quick-tunnel, of the DERP road alone, of --pinggy or of --opentunnel keeps the record of its \
             road at {n0} too. It does not where {env} names another server or off. A client whose ticket's relay \
             does not reach the node within {after} s asks for the record, {limit} s at most. It asks at once when \
             that relay does not answer /ping. It dials the relay that the record names too; podssh ssh then says \
             the node's ticket at that relay. podssh ssh node://NAME of a member of the net, whose key the net \
             names, asks it once each road with a ticket failed. It then races each road that the record names and \
             no ticket gave: the iroh road, the DERP road, the quick tunnel, and the OpenTunnel road where no \
             OpenTunnel name is given or kept; and the Pinggy road, last, with the record's address where \
             --pinggy-name gave none, as the record's signature makes its pin the node's word. A record that the \
             node's key did not sign is refused; of a record, a DERP ticket of another key is set aside, and so is \
             a quick tunnel that is not one name under trycloudflare.com. So is a Pinggy address that is not \
             NAME#PIN, or an OpenTunnel name that is not ROUTE.ID.DOMAIN of {opentunnel} bytes at most; and the \
             end-to-end channel checks the node's key on each road either way.",
            n0 = pkarr::n0_url(),
            env = pkarr::ENV,
            minutes = pkarr::REPUBLISH.as_secs() / 60,
            after = pod_iroh::client::FIND_AFTER.as_secs(),
            limit = pkarr::LIMIT.as_secs(),
            opentunnel = pkarr::record::MAX_OPENTUNNEL,
        ),
    )
}
