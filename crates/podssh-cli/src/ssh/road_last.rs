//! The last fallbacks of the operator's ruling Q78 in the race of `podssh
//! ssh node://NAME` (`super`), apart from `roads.rs` for its length: after a
//! node's Pinggy tunnel (T-548, which `roads.rs` races itself, by its
//! record), the pair's ZeroTier network (T-733, `crate::ssh::zerotier`), the
//! pair's key on a Tox relay (T-734, [`tox`]), the pair's key in Yggdrasil's
//! network (T-735, [`ygg`]), its key in HyperDHT where UDP passes (T-736,
//! [`dht`]), its device ID on a relay of Syncthing's (T-571, [`syncthing`]),
//! its onion service in the Tor network (T-578, [`onion`]), its channels at
//! smee.io's server (T-741, [`smee`]), a node's alias at
//! Serveo (T-549, `crate::ssh::serveo`), then its
//! name at ssh-j.com (T-570, `crate::ssh::sshj`), then its tunnel of HTTP
//! made by `ssh -R` (T-565, `super::ssh_http`), then its tunnel at srv.us,
//! whose name its key gives (T-566, [`srv_us`]), then its name at
//! localtunnel's server (T-568, [`localtunnel`]), then its port at bore.pub
//! (T-569, [`bore`]), then the tunnel's name of `ssh -R` through a Bare node
//! (T-740, [`bare`]), then the pair's pieces as sealed uploads to public
//! file hosts with their URLs at a public MQTT broker (T-738, [`filehost`]),
//! the last of all, as the slowest. The road that a host with 443 alone
//! can serve comes before the roads of raw TCP to another port, and bore's
//! raw port, which more cages refuse, comes last. Each starts as its own `push` says. The order is the node's
//! too: a node that would serve none of the roads before them unasked serves
//! them in this order.

use std::sync::Arc;

use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use super::Going;
use crate::ssh::road_link::Kind;

// croc's relay road of node://NAME, a last fallback of Q78 (T-694).
#[path = "croc.rs"]
pub(crate) mod croc;

// ZeroTier's road of node://NAME, a last fallback of Q78 after croc's (T-733).
#[path = "zerotier.rs"]
pub(crate) mod zerotier;

// The Tox road of node://NAME, a last fallback of Q78 after ZeroTier's (T-734).
#[path = "tox.rs"]
pub(crate) mod tox;
// Yggdrasil's road of node://NAME, a last fallback of Q78 after the Tox road's (T-735).
#[path = "ygg.rs"]
pub(crate) mod ygg;
// HyperDHT's road of node://NAME where UDP passes, after Yggdrasil's (T-736).
#[path = "hyperdht.rs"]
pub(crate) mod dht;
// Syncthing's relay road of node://NAME, a last fallback of Q78 after HyperDHT's (T-571).
#[path = "strelay.rs"]
pub(crate) mod syncthing;
// The onion road of node://NAME, a last fallback of Q78 after Syncthing's (T-578).
#[path = "onion.rs"]
pub(crate) mod onion;
// The smee.io road of node://NAME, a last fallback of Q78 after the onion road's (T-741).
#[path = "smee.rs"]
pub(crate) mod smee;

// The srv.us road of node://NAME, its name of the node's key (T-566).
#[path = "road_srv_us.rs"]
pub(crate) mod srv_us;

// The localtunnel road of node://NAME (T-568).
#[path = "localtunnel.rs"]
pub(crate) mod localtunnel;

// A port of the node's key at bore.pub (T-569).
#[path = "bore.rs"]
pub(crate) mod bore;

// The tunnel's name through a Bare node (T-740).
#[path = "road_bare.rs"]
pub(crate) mod bare;

// The GSRN road of node://NAME by a shared secret, before the file hosts' (T-707).
#[path = "gsr.rs"]
pub(crate) mod gsr;

// The file hosts' road of node://NAME, the last of all (T-738).
#[path = "filehost.rs"]
pub(crate) mod filehost;

/// The last fallbacks of one run, each where it races.
pub(crate) struct LastRoads {
    /// The pair's ZeroTier network (T-733), first of them.
    zerotier: Option<zerotier::ZeroTierRoads>,
    /// A Tox relay of the pair (T-734), after it.
    tox: Option<tox::ToxRoads>,
    /// Yggdrasil's network of the pair (T-735), after it.
    ygg: Option<ygg::YggRoads>,
    /// HyperDHT of the pair where UDP passes (T-736), after it.
    dht: Option<dht::DhtRoads>,
    /// A relay of Syncthing's of the pair (T-571), after it.
    syncthing: Option<syncthing::StRoads>,
    /// The node's onion service, of the pair's key (T-578), after it.
    onion: Option<onion::OnionRoads>,
    /// The pair's channels at smee.io's server (T-741), after it.
    smee: Option<smee::SmeeRoads>,
    serveo: Option<crate::ssh::serveo::ServeoRoads>,
    sshj: Option<crate::ssh::sshj::SshJRoads>,
    tunnel: Option<super::ssh_http::SshHttpRoads>,
    /// The node's tunnel at srv.us, its name of the node's key (T-566).
    srv_us: Option<srv_us::SrvUsRoads>,
    localtunnel: Option<localtunnel::LocalTunnelRoads>,
    bore: Option<bore::BoreRoads>,
    /// The Bare node of the hop of the tunnel's name, where the hop is on.
    bare: Option<podssh_ws::url::WsUrl>,
    /// The relay of gsocket, by the secret of the user's file (T-707).
    gsr: Option<gsr::GsrRoads>,
    /// The pair's pieces at public file hosts (T-738), the last of all.
    filehost: Option<filehost::FileHostRoads>,
}

impl LastRoads {
    /// The roads to the node `label`, each where its server is on and a key
    /// of the node, or a name of its tunnel, is known (`record`: whether the
    /// node's record is asked, which can name the tunnel); never with
    /// --no-e2e.
    pub(crate) fn new(
        label: &str,
        ask: &crate::channel::Ask,
        record: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Self {
        LastRoads {
            zerotier: None,
            tox: None,
            ygg: None,
            dht: None,
            syncthing: None,
            onion: None,
            smee: None,
            serveo: crate::ssh::serveo::ServeoRoads::new(label, ask, log, shown),
            sshj: crate::ssh::sshj::SshJRoads::new(label, ask, trust, log, shown),
            tunnel: super::ssh_http::SshHttpRoads::new(label, ask.off, record, trust, log, shown),
            srv_us: srv_us::SrvUsRoads::new(label, ask, trust, log, shown),
            localtunnel: localtunnel::LocalTunnelRoads::new(label, ask, trust, log, shown),
            bore: bore::BoreRoads::new(label, ask, trust, log, shown),
            // A bad PODSSH_BARE is refused before the race (`race` of the road).
            bare: bare::node().ok().flatten(),
            gsr: gsr::GsrRoads::new(ask, log, shown),
            filehost: None,
        }
    }

    /// The roads of a measure of `podssh ping`, which never sends a byte to
    /// a third party of Q78 unasked: a node's tunnel of `ssh -R` only when
    /// its name was given in this run, as Pinggy's; none of the others,
    /// which are never asked.
    pub(crate) fn asked(label: &str, trust: &Trust, log: &Arc<Log>, shown: &str) -> Self {
        let tunnel = super::ssh_http::SshHttpRoads::new(label, false, false, trust, log, shown);
        let tunnel = tunnel.filter(|tunnel| tunnel.asked());
        LastRoads {
            zerotier: None,
            tox: None,
            ygg: None,
            dht: None,
            syncthing: None,
            onion: None,
            smee: None,
            serveo: None,
            sshj: None,
            tunnel,
            srv_us: None,
            localtunnel: None,
            bore: None,
            bare: None,
            gsr: None,
            filehost: None,
        }
    }

    /// With the roads of the pair `part` to the node `label` that are on:
    /// ZeroTier's, then the Tox road, then Yggdrasil's, then HyperDHT's, then
    /// Syncthing's relay road, then the onion road, then the smee.io road,
    /// and the file hosts' road after each other road; none with --no-e2e
    /// (`off`).
    pub(crate) fn with_pair(
        self,
        label: &str,
        part: Option<&podssh_relay::pair::OperatorPart>,
        off: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Self {
        let zerotier = zerotier::ZeroTierRoads::new(part, off, log, shown);
        let tox = tox::ToxRoads::new(part, off, log, shown);
        let ygg = ygg::YggRoads::new(part, off, log, shown);
        let dht = dht::DhtRoads::new(part, off, log, shown);
        let syncthing = syncthing::StRoads::new(part, off, log, shown);
        let onion = onion::OnionRoads::new(label, part, off, trust, log, shown);
        let smee = smee::SmeeRoads::new(part, off, trust, log, shown);
        let filehost = filehost::FileHostRoads::new(part, off, log, shown);
        LastRoads { zerotier, tox, ygg, dht, syncthing, onion, smee, filehost, ..self }
    }

    /// Whether one of them races.
    pub(crate) fn any(&self) -> bool {
        let named = self.serveo.is_some() || self.sshj.is_some() || self.tunnel.is_some() || self.srv_us.is_some();
        named || self.localtunnel.is_some() || self.bore.is_some() || self.gsr.is_some()
    }

    /// Their places in the race, in their order; the onion road and the
    /// tunnel of `ssh -R` read the node's `record` at each link.
    pub(crate) fn push<'r>(
        &'r self,
        list: &mut Vec<(Start, Going<'r>)>,
        kinds: &mut Vec<Kind>,
        record: Option<&'r crate::ssh::iroh::RecordRoads<'_>>,
    ) {
        if let Some(zerotier) = &self.zerotier {
            zerotier.push(list, kinds);
        }
        if let Some(tox) = &self.tox {
            tox.push(list, kinds);
        }
        if let Some(ygg) = &self.ygg {
            ygg.push(list, kinds);
        }
        if let Some(dht) = &self.dht {
            dht.push(list, kinds);
        }
        if let Some(syncthing) = &self.syncthing {
            syncthing.push(list, kinds);
        }
        if let Some(onion) = &self.onion {
            onion.push(list, kinds, record);
        }
        if let Some(smee) = &self.smee {
            smee.push(list, kinds);
        }
        if let Some(serveo) = &self.serveo {
            serveo.push(list, kinds);
        }
        if let Some(sshj) = &self.sshj {
            sshj.push(list, kinds);
        }
        if let Some(tunnel) = &self.tunnel {
            tunnel.push(list, kinds, record);
        }
        if let Some(srv_us) = &self.srv_us {
            srv_us.push(list, kinds);
        }
        if let Some(localtunnel) = &self.localtunnel {
            localtunnel.push(list, kinds);
        }
        if let Some(bore) = &self.bore {
            bore.push(list, kinds);
        }
        if let (Some(tunnel), Some(node)) = (&self.tunnel, &self.bare) {
            tunnel.push_bare(node, list, kinds, record);
        }
        // The GSRN road, asked by its secret, before the slowest road of all.
        if let Some(gsr) = &self.gsr {
            gsr.push(list, kinds);
        }
        if let Some(filehost) = &self.filehost {
            filehost.push(list, kinds);
        }
    }
}
