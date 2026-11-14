//! The GSRN road of `podssh ssh node://NAME` (T-707), in a build with the
//! feature `gsr`: with the secret of `--gsr-secret-file` or
//! `PODSSH_GSR_SECRET_FILE`, a `CONNECT` at the relay of gsocket to the
//! address that the secret gives, where the node of `podssh node --gsr`
//! waits, then TLS with SRP of the same secret (`podssh_gsr`). The resumable
//! layer and the end-to-end channel run above it, as on each road of the
//! race, so the node's key is checked by the pins of NAME or `--node-key`,
//! and the relay sees sizes and times alone. It needs no pair here. It races
//! last, after the other roads failed: the user asked for it with the
//! secret, but its relay is a third party that nobody vouches for, which a
//! line names before its first link. Never with `--no-e2e`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::relay_settings::Refusal;
use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road's secret, checked: none in a build without the road, with
/// --no-e2e (`off`), or with no file named; a file or a secret that cannot
/// be used is refused (78) before anything connects.
fn chosen(off: bool) -> Result<Option<crate::gsr::Secret>, Refusal> {
    if off || !cfg!(feature = "gsr") {
        return Ok(None);
    }
    let Some(secret) = crate::gsr::secret(None)? else { return Ok(None) };
    #[cfg(feature = "gsr")]
    {
        let settings = podssh_gsr::settings().map_err(|why| Refusal::config(format!("the GSRN road: {why}")))?;
        podssh_gsr::check_secret(&settings, secret.expose())
            .map_err(|why| Refusal::config(format!("the GSRN road's secret: {why}")))?;
    }
    Ok(Some(secret))
}

/// Whether the road would race to a node, with the channel of `ask`.
pub(crate) fn named(ask: &crate::channel::Ask) -> Result<bool, Refusal> {
    chosen(ask.off).map(|secret| secret.is_some())
}

/// The road to the node of one run.
pub(crate) struct GsrRoads {
    secret: crate::gsr::Secret,
    #[cfg(feature = "gsr")]
    settings: podssh_gsr::Settings,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl GsrRoads {
    /// The road with this run's secret, when [`named`]; a refusal was said
    /// before the race (`super::node_roads`), so here it is a line of -v.
    pub(crate) fn new(ask: &crate::channel::Ask, log: &Arc<Log>, shown: &str) -> Option<GsrRoads> {
        let secret = match chosen(ask.off) {
            Ok(secret) => secret?,
            Err(refusal) => {
                log.verbose(&format!("{shown}: no GSRN road: {}", refusal.message));
                return None;
            }
        };
        #[cfg(feature = "gsr")]
        let settings = podssh_gsr::settings().ok()?;
        Some(GsrRoads {
            secret,
            #[cfg(feature = "gsr")]
            settings,
            said: AtomicBool::new(false),
            log: log.clone(),
            shown: shown.to_string(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Gsr);
    }

    async fn link(&self) -> Result<Road, String> {
        self.linked().await
    }

    #[cfg(feature = "gsr")]
    async fn linked(&self) -> Result<Road, String> {
        let host = podssh_gsr::host_of(&self.settings, self.secret.expose());
        // The line of the third party, before the first byte goes to it.
        if !self.said.swap(true, Ordering::SeqCst) {
            let party = podssh_gsr::party();
            self.log.info(&format!(
                "{}: the GSRN relay {host} of {party} carries this session: a third party that nobody vouches for, \
                 which sees its sizes and times; TLS with SRP of the shared secret and the end-to-end channel keep \
                 its bytes",
                self.shown
            ));
        }
        let dial = podssh_gsr::dialer(&podssh_ws::ProxyChoice::FromEnvironment);
        let role = podssh_gsr::Role::Connect;
        let stream = podssh_gsr::open(&*dial, &self.settings, role, self.secret.expose(), LIMIT)
            .await
            .map_err(|failure| format!("the GSRN relay {host}: {}", failure.chain()))?;
        Ok(Road::Gsr(Box::new(stream)))
    }

    #[cfg(not(feature = "gsr"))]
    async fn linked(&self) -> Result<Road, String> {
        // `named` and `new` give no road without the feature.
        let _ = (&self.secret, &self.said, &self.log, &self.shown);
        let _ = Ordering::SeqCst;
        Err(crate::gsr::not_built("the GSRN road"))
    }
}

/// How long a link waits for the relay's answer: at once when no node
/// waits there (its status 2), else the node's `ACCEPT`.
#[cfg(feature = "gsr")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
