//! How the first hop of `podssh ssh` is reached: the road that a resolved
//! command line names (`super::resolve`), apart for its length, as each
//! road of a server or a network adds a variant.

use podssh_relay::failover::Mode;
use podssh_relay::relay::RelayList;
use podssh_ws::Trust;

/// How the first hop is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Through the relay hosts, in order; `family` is 4 or 6 when asked. With
    /// `then_direct`, the direct road once each host failed or one reached no
    /// IPv6 host (T-363, T-253): no relay was named, nor `PODSSH_DIRECT=no`.
    Relay { relays: RelayList, trust: Trust, family: Option<u8>, failover: Mode, then_direct: bool },
    /// A TCP connection, through `HTTPS_PROXY` when one is set (`--direct`).
    Direct,
    /// The node of a pair, through the operator's leg of the reverse road
    /// (`node://NAME`, T-084); raced with its iroh road when `race` names
    /// one (T-164), and with its DERP road when `derp` gives a ticket or
    /// one is kept under NAME (T-379). With `carrier`, the stream of
    /// `--carrier`, unparsed, is its one road (T-595).
    Node {
        label: String,
        pair_file: Option<String>,
        trust: Trust,
        race: Option<super::iroh::Race>,
        derp: super::derp::Race,
        // Boxed: the variant is large beside the others.
        opentunnel: Box<super::opentunnel::Race>,
        channel: crate::channel::Ask,
        carrier: Option<String>,
    },
    /// A node over the iroh road (`iroh:TICKET`, T-163), with this client's
    /// key file when `--iroh-key` names one, and the relays to try after the
    /// ticket's (T-165).
    Iroh { ticket: String, key: Option<String>, relays: Vec<String>, trust: Trust, channel: crate::channel::Ask },
    /// The service that `cloudflared` publishes under `host`, over its
    /// WebSocket (`cf://HOST`, T-264), or a podssh node's quick tunnel,
    /// with the channel that the command line asks of a node (T-300).
    Cloudflare { host: String, trust: Trust, channel: crate::channel::Ask },
    /// A VM through its cloud's own tunnel (`iap://`, `eice://`, T-351).
    Cloud { road: super::cloud::Road, trust: Trust },
    /// A node over the DERP road (`derp:TICKET`, T-379), at the servers in
    /// the order that they are tried, the ticket's first.
    Derp {
        ticket: podssh_relay::derp::Ticket,
        servers: Vec<podssh_relay::derp::Server>,
        trust: Trust,
        channel: crate::channel::Ask,
    },
    /// Through other products' WebSocket forwarders, in order (T-369).
    Forwarder { forwarders: Vec<crate::forwarder::Forwarder>, trust: Trust },
    /// Through the Shadowsocks servers of a file, in order (T-373).
    Shadowsocks { servers: crate::shadowsocks::Servers, trust: Trust },
    /// Through a forward proxy over TLS that the user runs (`--via`, T-439).
    Via { road: crate::via::Road },
    /// Through the VLESS servers of a file, in order (`--vless`, T-440).
    Vless { servers: crate::vless::Servers, trust: Trust },
    /// Through a wstunnel server that the user runs (`--wstunnel`, T-441).
    Wstunnel { road: crate::wstunnel::Road },
    /// Through a chisel server that the user runs (`--chisel`, T-490).
    Chisel { road: crate::chisel::Road },
    /// Through the Trojan servers of a file, in order (`--trojan`, T-491).
    Trojan { servers: crate::trojan::Servers, trust: Trust },
    /// Through the TUIC servers of a file, where UDP passes (`--tuic`, T-581).
    Tuic { servers: crate::tuic::Servers, trust: Trust },
    /// Through the Hysteria 2 servers of a file, where UDP passes (T-580).
    Hysteria { servers: crate::hysteria::Servers, trust: Trust },
}
