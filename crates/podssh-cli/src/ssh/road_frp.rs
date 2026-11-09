//! The frp road of a client (T-498): with `PODSSH_FRP` naming the node's
//! file, a visit to the node's STCP service at the user's frps, with the
//! same secret (`podssh_ws::frp::node::visit`). The end-to-end channel and
//! the resumable layer run above it, as on the pair's road, so that frps
//! carries bytes it cannot read. The road races only when each road before
//! it failed: frps is the user's own fallback, and the ends' roads come first.
//!
//! A file with the line `plain` names a real frpc's STCP service of a plain
//! TCP service, an sshd: no podssh node is behind it, so no race and no
//! layer. SSH runs on the visit itself ([`ssh`]), and a copy's SSH too
//! ([`reach`]); the node's name is the known hosts' name, as on each road.

use std::sync::Arc;

use podssh_relay::session::race::Start;
use podssh_ssh::{Log, Options, EXIT_FAILURE};
use podssh_ws::frp::node::Road as FrpRoad;
use podssh_ws::Trust;
use tokio::io::DuplexStream;

use super::{Going, Kind, Road};
use crate::relay_settings::Refusal;
use crate::ssh::resolve::Transport;
use crate::ssh::transport::{NotReached, Reached};

/// The road to the node's service through frps.
pub(crate) struct FrpRoads {
    road: FrpRoad,
    /// The service's name: the file's `name`, else the node's label.
    name: String,
}

impl FrpRoads {
    /// The road that `PODSSH_FRP` names, to the node `label`; none when the
    /// variable names no file, or a file of a plain service, which no race
    /// takes ([`Plain`]). A file that does not read is refused, not passed
    /// over: the user asked for the road.
    pub(crate) fn new(label: &str, trust: &Trust) -> Result<Option<FrpRoads>, Refusal> {
        let Some(frp) = crate::frp_file::from_env(trust.clone())? else { return Ok(None) };
        if frp.plain {
            return Ok(None);
        }
        let name = frp.name.unwrap_or_else(|| label.to_string());
        Ok(Some(FrpRoads { road: frp.road, name }))
    }

    /// The road's place in the race, after each road before it failed.
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Frp);
    }

    async fn link(&self) -> Result<Road, String> {
        let shown = self.road.server.shown();
        let stream = podssh_ws::frp::node::visit(&self.road, &self.name).await.map_err(|e| format!("{shown}: {e}"))?;
        Ok(Road::Pair(stream))
    }
}

/// A plain service of a real frpc, which `PODSSH_FRP`'s file names with
/// its line `plain`.
pub(crate) struct Plain {
    road: FrpRoad,
    name: String,
}

impl Plain {
    /// The plain service that `PODSSH_FRP` names for `node://LABEL`; none
    /// when the variable names no file, or a podssh node's. A route, or the
    /// node key that the end-to-end channel would check, has nothing to
    /// apply to (64).
    pub(crate) fn of(label: &str, trust: &Trust, ask: &crate::channel::Ask) -> Result<Option<Plain>, Refusal> {
        let Some(frp) = crate::frp_file::from_env(trust.clone())? else { return Ok(None) };
        if !frp.plain {
            return Ok(None);
        }
        let shown = super::super::node::shown(label, None);
        if let Some(route) = &ask.route {
            let why = format!("{shown}/{route}: the plain service of PODSSH_FRP has no routes, as frpc's has none");
            return Err(Refusal::usage(why));
        }
        if ask.node_key.is_some() {
            let why = format!(
                "{shown}: --node-key does not go with the plain service of PODSSH_FRP: no end-to-end channel runs \
                 on it, and the known hosts check its SSH host key"
            );
            return Err(Refusal::usage(why));
        }
        let name = frp.name.unwrap_or_else(|| label.to_string());
        Ok(Some(Plain { road: frp.road, name }))
    }

    /// The visit's stream, SSH's bytes in clear but for SSH's own cipher.
    pub(crate) async fn visit(&self, log: &Log, shown: &str) -> Result<DuplexStream, String> {
        let at = self.road.server.shown();
        let service = self.road.visited(&self.name);
        log.verbose(&format!(
            "{shown}: the plain STCP service {service} through {at}, with SSH on the visit: no end-to-end channel"
        ));
        podssh_ws::frp::node::visit(&self.road, &self.name).await.map_err(|e| format!("{shown}: {at}: {e}"))
    }
}

/// The plain service of `transport` at its frps, as `podssh ssh` takes it:
/// SSH on the visit; none when `PODSSH_FRP` names no plain service, and the
/// node's other roads go on.
pub(crate) async fn ssh(transport: &Transport, opts: &Options, log: Arc<Log>) -> Option<i32> {
    let Transport::Node { label, trust, channel, .. } = transport else { return None };
    let plain = match Plain::of(label, trust, channel) {
        Ok(Some(plain)) => plain,
        Ok(None) => return None,
        Err(refusal) => {
            log.error(&refusal.message);
            return Some(refusal.code);
        }
    };
    let shown = super::super::node::shown(label, None);
    let visited = plain.visit(&log, &shown).await;
    match visited {
        Ok(stream) => Some(Box::pin(podssh_ssh::run(stream, opts, None, log)).await),
        Err(why) => {
            log.error(&why);
            podssh_ssh::outcome::failed("connect");
            Some(EXIT_FAILURE)
        }
    }
}

/// The plain service of the node `label` for a copy (`cp`, `scp`, `sftp`):
/// the visit's stream, on which the copy's SSH runs; none as [`ssh`].
pub(crate) async fn reach(
    label: &str,
    trust: &Trust,
    ask: &crate::channel::Ask,
    log: &Log,
) -> Option<Result<Reached, NotReached>> {
    let refused = |refusal: Refusal| NotReached { lines: vec![refusal.message], code: refusal.code };
    let plain = match Plain::of(label, trust, ask) {
        Ok(Some(plain)) => plain,
        Ok(None) => return None,
        Err(refusal) => return Some(Err(refused(refusal))),
    };
    let shown = super::super::node::shown(label, None);
    Some(match plain.visit(log, &shown).await {
        Ok(stream) => Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None }),
        Err(why) => Err(NotReached { lines: vec![why], code: EXIT_FAILURE }),
    })
}
