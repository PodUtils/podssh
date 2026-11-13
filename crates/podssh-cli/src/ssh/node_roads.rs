//! The roads of a `node://NAME` destination beside its pair's (T-551), chosen
//! once for `podssh ssh` and for the copies, so that the two cannot drift:
//! the iroh road of a ticket, the DERP and OpenTunnel roads of a ticket or a
//! name given, of the net or kept, the transit relay, the Piping Server road
//! and the member's record of pkarr. With one of them, `ssh` races them with
//! the pair's ([`connect`]), and so does a copy (`cp`, `mv`, `scp`, `sftp`
//! and `edit`, [`reach`]), in the same order with the same delays: the race
//! of `super::roads` runs in a task of its own, which owns what the roads
//! borrow, and hands the layered stream to the copy, whose SSH runs on it as
//! on the first hop of any road. With none, the pair's road alone, and the
//! Piping Server road once it found the WebSocket upgrade refused on the way
//! (T-437, Q65), for both.

use std::sync::Arc;

use podssh_ssh::handshake::Flow;
use podssh_ssh::{Log, Options, EXIT_FAILURE};
use podssh_ws::url::WsUrl;
use podssh_ws::Trust;
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

use super::iroh::RecordAsk;
use super::resolve::Transport;
use super::road_link::{Handed, Rider};
use super::roads::Raced;
use super::transport::{NotReached, Reached};
use crate::exitmap::sysexits;
use crate::layered::Shell;
use crate::relay_settings::Refusal;

/// The parts of a `node://NAME` destination with no carrier that its roads
/// take.
#[derive(Clone, Copy)]
pub(super) struct Dest<'a> {
    pub label: &'a str,
    pub pair_file: Option<&'a str>,
    pub trust: &'a Trust,
    /// The iroh road of `--iroh-ticket`, or of the net (T-164, T-429).
    pub race: Option<&'a super::iroh::Race>,
    pub derp: &'a super::derp::Race,
    pub opentunnel: &'a super::opentunnel::Race,
    pub channel: &'a crate::channel::Ask,
}

impl<'a> Dest<'a> {
    /// The node of `transport` with no carrier; `None` for another road.
    pub(super) fn of(transport: &'a Transport) -> Option<Dest<'a>> {
        let Transport::Node { label, pair_file, trust, race, derp, opentunnel, channel, carrier: None } = transport
        else {
            return None;
        };
        let (pair_file, race) = (pair_file.as_deref(), race.as_ref());
        Some(Dest { label, pair_file, trust, race, derp, opentunnel, channel })
    }
}

/// The roads of one run beside the pair's and the iroh ticket's, each its
/// own, so that a copy's task can own them.
struct Chosen {
    /// The member's record of pkarr, for each road that no ticket gave (T-445).
    record: Option<RecordAsk>,
    derp: Option<super::derp::Road>,
    opentunnel: Option<super::opentunnel::Road>,
    transit: Option<WsUrl>,
    piping: Option<crate::piping_road::Race>,
    /// Whether a member of the net with the relay role carries a leg to the
    /// node (T-434): a client with no pair here races those legs alone.
    members: bool,
    /// Whether `PODSSH_FRP` names a visit to the node at the user's frps
    /// (T-498), which needs no pair here either.
    frp: bool,
    /// Whether a Pinggy name of the node is given or kept (T-548).
    pinggy: bool,
    /// Whether a key of the node gives its alias at Serveo (T-549).
    serveo: bool,
    /// Whether the node's name at ssh-j.com can be derived (T-570).
    sshj: bool,
    /// Whether the node's name at localtunnel's server can be derived (T-568).
    localtunnel: bool,
    /// Whether the node's ports at bore.pub can be derived (T-569).
    bore: bool,
    /// Whether croc's relay road is on, with a good pair here (T-694).
    croc: bool,
    /// Whether ZeroTier's road or another road of the pair's secret after it
    /// (T-734 to T-736, T-571, T-578) is on in this build, with a good pair
    /// here (T-733).
    zerotier: bool,
    /// Whether a name of the node's tunnel of `ssh -R` is given or kept (T-565).
    tunnel: bool,
}

impl Chosen {
    /// Whether a road races beside the pair's: else the pair's road alone.
    /// The Piping Server road that nobody asked for waits for its cue there.
    fn races(&self, dest: &Dest<'_>) -> bool {
        let piping_asked = self.piping.as_ref().is_some_and(|road| road.asked);
        let others =
            self.derp.is_some() || self.opentunnel.is_some() || self.transit.is_some() || self.record.is_some();
        let pair_last = self.croc || self.zerotier;
        let last = self.pinggy || self.serveo || self.sshj || pair_last || self.tunnel || self.localtunnel || self.bore;
        dest.race.is_some() || others || piping_asked || self.members || self.frp || last
    }
}

/// The roads of a run to the node of `dest` beside the pair's, each checked
/// before anything connects: a bad variable is refused (78).
fn chosen(dest: &Dest<'_>) -> Result<Chosen, Refusal> {
    let Dest { label, pair_file, trust, race, derp, opentunnel, channel } = *dest;
    // The member's record of pkarr, for each road that no ticket gave
    // (T-445): a bad variable of it is said before anything connects.
    let record = super::iroh::record_ask(label, race.is_some(), derp, opentunnel, channel)?;
    // The DERP road: the ticket given, else the one kept under the label
    // (Q50); never with --no-e2e, as its node's door is the channel.
    let derp = derp.road(label).filter(|_| !channel.off);
    // The OpenTunnel road (T-531): the name given, else the one kept under
    // the label (Q76); never with --no-e2e, as its node's door is the channel.
    let opentunnel = opentunnel.road(label).filter(|_| !channel.off);
    // The transit relay of the pair (T-436, Q65): never with --no-e2e,
    // and only with a good pair here, whose token it is; with none, the
    // pair's road says why, as before.
    let good_pair = || crate::pairs::operator_part(label, pair_file).is_ok();
    let transit = crate::node_transit::url().filter(|_| !channel.off && good_pair());
    // The Piping Server road (T-437): asked, or the fallback of Q65 once
    // the upgrade is refused; never with --no-e2e, as its server would
    // see each byte.
    let piping = crate::piping_road::race()?.filter(|_| !channel.off);
    // The legs at the net's relay members, never with --no-e2e, as the
    // member would see each byte (T-434).
    let members = !channel.off && super::roads::member::MemberRoads::new(label, trust).is_some();
    // A bad PODSSH_FRP is refused here, before anything connects; never with
    // --no-e2e, as frps would see each byte.
    let frp = super::roads::frp::FrpRoads::new(label, trust)?.is_some() && !channel.off;
    // The Pinggy road (T-548): a name given or kept, never with --no-e2e.
    let pinggy = super::pinggy::named(label, channel.off);
    // The Serveo road (T-549): a key of the node known, never with --no-e2e.
    let serveo = super::serveo::named(label, channel);
    // The ssh-j road (T-570): a key to derive the name from, never with --no-e2e.
    let sshj = super::sshj::named(label, channel);
    // The localtunnel road (T-568): the same.
    let localtunnel = super::roads::last::localtunnel::named(label, channel);
    // The bore road (T-569): the same key gives its ports, never with --no-e2e; the last of all.
    let bore = super::roads::last::bore::named(label, channel);
    // croc's relay road (T-694, Q78), as the transit relay's: never with --no-e2e, with a good pair.
    let croc = crate::node_croc::bridge().is_some() && !channel.off && good_pair();
    // ZeroTier's road (T-733, Q78), as croc's; a bad PODSSH_ZEROTIER or planet is refused here.
    let zerotier_on = matches!(crate::zerotier::setting()?, crate::zerotier::Setting::On(..))
        && cfg!(all(feature = "zerotier", unix));
    // The Tox road (T-734, Q78), as ZeroTier's; a bad PODSSH_TOX is refused here.
    let tox_on = matches!(crate::tox::setting()?, crate::tox::Setting::On(..)) && cfg!(feature = "tox");
    // Yggdrasil's road (T-735, Q78), as the Tox road's; a bad PODSSH_YGGDRASIL is refused here.
    let ygg_on =
        matches!(crate::yggdrasil::setting()?, crate::yggdrasil::Setting::On(..)) && cfg!(feature = "yggdrasil");
    // HyperDHT's road (T-736, Q77, Q82), as Yggdrasil's; a bad PODSSH_HYPERDHT is refused here.
    let dht_on = matches!(crate::hyperdht::setting()?, crate::hyperdht::Setting::On(..)) && cfg!(feature = "hyperdht");
    // Syncthing's relays (T-571, Q78), as the Tox road's; a bad PODSSH_SYNCTHING_RELAY is refused here.
    let st_on = matches!(crate::strelay::setting()?, crate::strelay::Setting::On(..)) && cfg!(feature = "strelay");
    // The onion road (T-578, Q78), as Syncthing's; a bad PODSSH_ONION is refused here.
    let onion_on = matches!(crate::onion::setting()?, crate::onion::Setting::On(..)) && cfg!(feature = "tor");
    // The smee.io road (T-741, Q78), after the onion road; a bad PODSSH_SMEE is refused here.
    let smee_on = matches!(crate::smee_road::setting()?, crate::smee_road::Setting::On(..));
    // The file hosts' road (T-738, Q78), the last of all; a bad PODSSH_FILEHOSTS is refused here.
    let filehost_on =
        matches!(crate::filehost_road::setting()?, crate::filehost_road::Setting::On(..)) && cfg!(feature = "filehost");
    let pair_last = zerotier_on || tox_on || ygg_on || dht_on || st_on || onion_on || smee_on || filehost_on;
    let zerotier = pair_last && !channel.off && good_pair();
    // localhost.run's road (T-565): a name given or kept, never with --no-e2e;
    // or srv.us's (T-566), whose name the node's whole key gives.
    let srv_us = super::roads::last::srv_us::named(label, channel);
    let tunnel = super::roads::ssh_http::named(label, channel.off) || srv_us;
    Ok(Chosen {
        record,
        derp,
        opentunnel,
        transit,
        piping,
        members,
        frp,
        pinggy,
        serveo,
        sshj,
        croc,
        zerotier,
        tunnel,
        localtunnel,
        bore,
    })
}

/// SSH to the node of `dest`: over the race of its roads beside the pair's,
/// when one is given, kept or on; else over the pair's road
/// (`super::node::connect`).
pub(super) async fn run(dest: Dest<'_>, opts: &Options, log: Arc<Log>) -> i32 {
    let chosen = match chosen(&dest) {
        Ok(chosen) => chosen,
        Err(refusal) => {
            log.error(&refusal.message);
            return refusal.code;
        }
    };
    let Dest { label, pair_file, trust, race, channel, .. } = dest;
    if !chosen.races(&dest) {
        let piping = chosen.piping.as_ref();
        return Box::pin(super::node::connect(label, pair_file, trust, piping, channel, opts, log)).await;
    }
    let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
    let raced = Raced { iroh: race, derp, opentunnel, transit, piping, record: record.as_ref() };
    Box::pin(connect(label, pair_file, trust, raced, channel, opts, log)).await
}

/// SSH to the node of the pair under `label`, over the first of its roads
/// that answers, again at each resume.
pub(super) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    raced: Raced<'_>,
    ask: &crate::channel::Ask,
    opts: &Options,
    log: Arc<Log>,
) -> i32 {
    // What the layer and the channel carry, for the line of a handshake that
    // does not finish (T-588); the far end's shells (T-158) and its silence
    // (T-302). SIGHUP and SIGTERM end the session with its `CLOSE`, as on
    // the pair's road alone; Ctrl-C stays the remote command's (T-586).
    let flow = Arc::new(Flow::default());
    let shell = Shell { offer: &opts.keep.offer, silence: &opts.silence, flow: Some(&flow) };
    let rider = Rider { shell: Some(shell), take: Some(crate::hangup::Which::Ends) };
    let (road_flow, ssh_log) = (&flow, log.clone());
    let ssh = move |handed: Result<Handed, NotReached>| async move {
        match handed {
            Ok(Handed { stream, channel }) => {
                let opts = super::node::on_the_road(opts, road_flow, channel);
                Some(Box::pin(podssh_ssh::run(stream, &opts, None, ssh_log)).await)
            }
            Err(not) => {
                for line in &not.lines {
                    ssh_log.error(line);
                }
                Some(EXIT_FAILURE)
            }
        }
    };
    let ridden = super::roads::ride(label, pair_file, trust, raced, ask, rider, log, ssh);
    Box::pin(ridden).await.unwrap_or(EXIT_FAILURE)
}

/// The stream to the node of `transport` for a copy (T-296, T-551): over the
/// race of its roads beside the pair's, when one is given, kept or on, in a
/// task that carries the session in the layer and races the roads again at
/// each resume; else over the pair's road alone (`super::node::reach`). When
/// the carriage fails, the task says why, and SSH sees its stream end.
pub(crate) async fn reach(transport: &Transport, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let Some(dest) = Dest::of(transport) else {
        let why = "the roads of a node were asked for another destination".to_string();
        return Err(NotReached { lines: vec![why], code: sysexits::EX_SOFTWARE });
    };
    let refused = |refusal: Refusal| NotReached { lines: vec![refusal.message], code: refusal.code };
    // A plain service of a real frpc is the node's one road (T-498).
    if let Some(reached) = super::roads::frp::reach(dest.label, dest.trust, dest.channel, log).await {
        return reached;
    }
    let mut chosen = chosen(&dest).map_err(refused)?;
    let Dest { label, pair_file, trust, race, channel, .. } = dest;
    if !chosen.races(&dest) {
        match super::node::reach(label, pair_file, trust, channel, log).await {
            Ok(reached) => return Ok(reached),
            // The upgrade refused on the way: the Piping Server road, as
            // `podssh ssh` takes it then (T-437, Q65).
            Err((not, true)) if chosen.piping.is_some() => {
                for line in &not.lines {
                    log.verbose(&format!("{line}: the upgrade was refused on the way; the Piping Server road"));
                }
                chosen.piping = chosen.piping.map(|race| race.refused());
            }
            Err((not, _)) => return Err(not),
        }
    }
    let shown = super::node::shown(label, None);
    let (give, given) = oneshot::channel::<Result<DuplexStream, NotReached>>();
    let (ended, done) = oneshot::channel();
    let (label, pair_file, trust) = (label.to_string(), pair_file.map(str::to_string), trust.clone());
    let (race, ask, log) = (race.cloned(), channel.clone(), log.clone());
    // A copy's streams go below a terminal's on a shared iroh connection (T-666).
    tokio::spawn(super::iroh::as_bulk(async move {
        let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
        let raced = Raced { iroh: race.as_ref(), derp, opentunnel, transit, piping, record: record.as_ref() };
        // The copy's SSH runs at the other end of the stream: no code here.
        let hand = move |handed: Result<Handed, NotReached>| {
            let _ = give.send(handed.map(|handed| handed.stream));
            std::future::ready(None)
        };
        let rider = Rider { shell: None, take: None };
        Box::pin(super::roads::ride(&label, pair_file.as_deref(), &trust, raced, &ask, rider, log, hand)).await;
        let _ = ended.send(());
    }));
    match given.await {
        Ok(Ok(stream)) => Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: Some(done) }),
        Ok(Err(not)) => Err(not),
        Err(_) => Err(NotReached {
            lines: vec![format!("{shown}: the task of the race ended before it handed its stream")],
            code: sysexits::EX_SOFTWARE,
        }),
    }
}

/// The roads of the node of `transport`, each timed to its far end's first
/// bytes, for `podssh ping node://NAME` (T-435): the roads that `ssh` races,
/// chosen as it chooses them, in its order with its delays, and the pair's
/// road with them also where `ssh` takes it alone; no session above them.
pub(crate) async fn measure(
    transport: &Transport,
    log: &Arc<Log>,
) -> Result<super::roads::probe::Measures, super::transport::NotReached> {
    let Some(dest) = Dest::of(transport) else {
        let why = "the roads of a node were asked for another destination".to_string();
        return Err(NotReached { lines: vec![why], code: sysexits::EX_SOFTWARE });
    };
    let chosen = chosen(&dest).map_err(|refusal| NotReached { lines: vec![refusal.message], code: refusal.code })?;
    let Dest { label, pair_file, trust, race, .. } = dest;
    let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
    let raced = Raced { iroh: race, derp, opentunnel, transit, piping, record: record.as_ref() };
    super::roads::probe::measure(label, pair_file, trust, raced, log.clone()).await
}
