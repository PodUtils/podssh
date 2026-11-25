//! The HTTP/2 road that podssh dials itself when `--h2-shape` chose a shape
//! (T-763). `pod-relay`'s opener takes `pod_ws::h2_road` directly, and that
//! road sends its own SETTINGS with no shape; a run that named one therefore
//! opens its session here, on `podssh_ws::h2_road`, whose `connect_with_shape`
//! is the road that sends it.
//!
//! One shape is one road: this opener tries the first relay host alone (no
//! failover to a host that may offer no extended CONNECT), it goes over TLS
//! alone (a shape is TLS's HTTP/2; there is no cleartext shape and no
//! HTTP/1.1 shape), and a failure is that host's failure rather than a
//! silent second attempt without the shape. A run that chose no shape calls
//! [`podssh_relay::open`] exactly as before.

use podssh_relay::open::{Failure, OpenError, Opened, Request, CONNECT_TIMEOUT};
use podssh_relay::token::{self, MintContext};
use podssh_ws::{Endpoint, ProxyChoice, WsClientConfig};

use crate::h2_choice;

/// Open `req` on the shaped HTTP/2 road, with the delegated credential of a
/// cover relay, or by [`podssh_relay::open`] where this run chose neither.
pub async fn open(req: &Request<'_>, notes: &mut (dyn FnMut(&str) + Send)) -> Result<Opened, Failure> {
    let shape = h2_choice::selected();
    let covered = crate::cover_choice::on();
    if shape.is_none() && !covered {
        return podssh_relay::open(req, notes).await;
    }
    let relay = req.relays.primary().clone();
    let ctx = podssh_relay::context::process();
    if ctx.settings.offline {
        return Err(Failure { attempts: vec![(relay.host.clone(), OpenError::Offline)] });
    }
    let what = match (&shape, covered) {
        (Some(_), _) => "the shape that --h2-shape chose",
        (None, true) => "the cover credential that --cover-credential asked for",
        (None, false) => unreachable!("a run that chose nothing returned above"),
    };
    notes(&format!("the road to {} carries {what}", relay.host));
    let mint = MintContext { ctx: &ctx, relay: &relay, trust: req.trust, timeout: CONNECT_TIMEOUT };
    let token = match token::obtain(&mint, false).await {
        Ok(token) => token,
        Err(e) => return Err(Failure { attempts: vec![(relay.host.clone(), OpenError::Token(e))] }),
    };
    if let Some(note) = token.cache_warning.clone() {
        notes(&format!("the relay token could not be cached, so one is minted per run: {note}"));
    }
    if let Some(note) = token.cache_note.clone() {
        notes(&note);
    }
    let config = WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path: req.path.to_string() },
        trust: req.trust.clone(),
        server_name: relay.host.clone(),
        timeout: CONNECT_TIMEOUT,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: ProxyChoice::FromEnvironment,
    };
    let opened = match &shape {
        Some(shape) => podssh_ws::h2_road::connect_with_shape(&config, token.secret(), shape)
            .await
            .map(|(session, road)| (session, road.words())),
        None => podssh_ws::client::connect_with_cover(&config, token.secret(), rand::random())
            .await
            .map(|session| (session, None))
            .map_err(|error| match error {
                podssh_ws::client::CoverError::Connect(error) => error,
                podssh_ws::client::CoverError::Credential(error) => podssh_ws::client::ConnectError::Http(format!(
                    "the cover credential: {}",
                    podssh_ws::text::said(&error)
                )),
            }),
    };
    match opened {
        Ok((session, words)) => {
            // The relay's own limits, as `pod-relay`'s opener takes them: the
            // budgets of the run go under them (T-342).
            let limits = podssh_relay::pool::cached_limits(&relay.host);
            podssh_relay::pool::set_in_use(limits);
            session.set_receive_cap(podssh_ws::frame::receive_cap(limits.max_frame_bytes));
            let session = match words {
                Some(words) => session.with_road(words),
                None => session,
            };
            Ok(Opened { session, relay, cleartext: false })
        }
        // The shape did not open the session, and a second attempt without
        // it would send no shape while the user asked for one: the failure
        // is the shape's road's.
        Err(error) => {
            Err(Failure { attempts: vec![(relay.host.clone(), OpenError::Connect { error, origin: token.origin })] })
        }
    }
}
