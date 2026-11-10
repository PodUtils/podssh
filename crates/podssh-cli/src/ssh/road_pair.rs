//! The links of the pair's road and of the Piping Server road, each a place
//! of `super`'s race, the race's words of its fallbacks that nobody asked
//! for, and whether any road can link again. Apart from `roads.rs`, for the
//! length of that file.

use std::sync::atomic::{AtomicBool, Ordering};

use podssh_relay::reverse::{legs, OperatorConfig, Outcome as LegOutcome};
use podssh_relay::session::race::{Start, HEAD_START};
use tokio::task::JoinHandle;

use super::{Going, Kind, Road, Roads, PIPE};
use crate::layered;
use crate::ssh::road_link::Unasked;

impl Roads<'_> {
    /// The Piping Server road's place in the race, when it has a dialer.
    pub(super) fn push_piping<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        if let Some((dialer, asked)) = &self.piping {
            // Unasked, the fallback: only when each road before it failed.
            let start = if *asked { Start::After(HEAD_START) } else { Start::WhenAllFailed };
            list.push((start, Box::pin(piping_link(dialer, *asked, &self.refused))));
            kinds.push(Kind::Piping);
        }
    }

    /// The roads that race as fallbacks which nobody asked for, for `-v`.
    pub(super) fn unasked(&self) -> Unasked {
        let unasked = |asked: Option<&bool>| asked == Some(&false);
        Unasked {
            derp: unasked(self.derp.as_ref().map(|(_, asked)| asked)),
            opentunnel: unasked(self.opentunnel.as_ref().map(|(_, asked)| asked)),
            piping: unasked(self.piping.as_ref().map(|(_, asked)| asked)),
            pinggy: self.pinggy.as_ref().and_then(|pinggy| pinggy.unasked()),
        }
    }

    /// Whether no road can give a link again: the pair's ended for good or
    /// is not there, the iroh road's node refused this client or it is not
    /// there, and there is no DERP road or Piping Server road, whose node
    /// may come back.
    pub(super) async fn ended_for_good(&self) -> bool {
        let others = self.opentunnel.is_some() || self.record.is_some() || self.member.is_some() || self.frp.is_some();
        let last = self.pinggy.is_some() || self.last.any() || self.croc.is_some();
        if self.derp.is_some() || others || last || self.piping_on() {
            return false;
        }
        let pair_done = self.pair.is_none() || self.pair_final.load(Ordering::SeqCst);
        let iroh_done = match &self.iroh {
            Some(iroh) => iroh.refused().await,
            None => true,
        };
        pair_done && iroh_done
    }

    /// Whether the Piping Server road may be tried: asked, or cued.
    pub(super) fn piping_on(&self) -> bool {
        self.piping.as_ref().is_some_and(|(_, asked)| *asked || self.refused.load(Ordering::SeqCst))
    }
}

/// A new leg of the pair's road, unless the last one ended with a close
/// that a new leg would only get again.
pub(super) async fn pair_link(
    config: &OperatorConfig<'_>,
    roads: &Roads<'_>,
    previous: Option<JoinHandle<LegOutcome>>,
) -> Result<Road, String> {
    if let Some(handle) = previous {
        if let Ok(Ok(outcome)) = tokio::time::timeout(layered::LEG_WAIT, handle).await {
            if let Some(stop) = layered::stops(&outcome) {
                roads.pair_final.store(true, Ordering::SeqCst);
                return Err(stop);
            }
        }
    }
    if roads.pair_final.load(Ordering::SeqCst) {
        return Err("the pair's road ended for good".to_string());
    }
    let (link, leg_end) = tokio::io::duplex(PIPE);
    match legs::start(config, leg_end).await {
        Ok(handle) => {
            *layered::lock(&roads.legs) = Some(handle);
            Ok(Road::Pair(link))
        }
        Err(e) => {
            // A proxy's refusal of the upgrade is the Piping Server road's
            // cue, and no word of the relay's on the pair.
            if roads.piping.is_some() && podssh_relay::piping::probe::upgrade_refused(&e) {
                roads.refused.store(true, Ordering::SeqCst);
            } else if layered::is_final(&e) {
                roads.pair_final.store(true, Ordering::SeqCst);
            }
            Err(crate::pairs::connect_refusal(&e, roads.label).message)
        }
    }
}

/// A link of the Piping Server road: asked, or once a road found the
/// upgrade refused.
pub(super) async fn piping_link(
    dialer: &podssh_relay::piping::Dialer,
    asked: bool,
    refused: &AtomicBool,
) -> Result<Road, String> {
    if !asked && !refused.load(Ordering::SeqCst) {
        return Err("not tried: no road found the WebSocket upgrade refused, and PODSSH_PIPING did not ask".into());
    }
    dialer.link().await.map(Road::Piping)
}
