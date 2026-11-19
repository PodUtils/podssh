//! The run of `podssh ssh`, and a new try of it after a drop of the relay
//! (T-025), apart from `mod.rs` for its length.

use std::sync::Arc;

use podssh_ssh::Log;

use super::*;

/// The run, and a new try of it after a drop of the relay that came before
/// any request reached the destination (T-025): to the next relay host when
/// the link to the relay broke, once more when the relay lost the target.
/// Each try says why, with the backoff of a failed upgrade; the tries in all
/// are at most the rounds of `ConnectionAttempts` times the relay hosts, and
/// a try after the first asks nothing: a key that a passphrase opened and a
/// password that the server took are used again, and a login that needs a
/// prompt stops. Its exit code, and the relay leg's status of the last try.
pub(super) async fn tries(resolved: &Resolved, log: &Arc<Log>) -> (i32, Option<podssh_ssh::RelayStatus>) {
    let mut opts = resolved.options.clone();
    opts.remembered.get_or_insert_with(Default::default);
    let hosts = match &resolved.transport {
        Transport::Relay { relays, .. } => relays.hosts.len().max(1),
        _ => 1,
    };
    let most = (resolved.connection_attempts.max(1) as usize).saturating_mul(hosts);
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&first.host, first.port);
    let (mut tried, mut skip, mut again) = (0usize, 0usize, false);
    // The relay's lines once it reached no IPv6 host, for the direct road
    // that the next try takes (T-253).
    let (started, mut unreached) = (tokio::time::Instant::now(), None);
    loop {
        tried += 1;
        let reached = match unreached.take() {
            Some(relay) => Box::pin(transport::after_ipv6_close(resolved, relay, started.elapsed(), log)).await,
            None => crate::layer_told::claimed(transport::reach_skipping(resolved, skip, log)).await,
        };
        let reached = match reached {
            Ok(reached) => reached,
            Err(failure) => {
                for line in &failure.lines {
                    log.error(line);
                }
                let leg = if matches!(resolved.transport, Transport::Relay { .. }) { "relay" } else { "connect" };
                podssh_ssh::outcome::failure_is(leg);
                return (EXIT_FAILURE, None);
            }
        };
        let relay = reached.relay.clone();
        let direct_proxy = reached.direct_proxy.clone();
        // A podssh node behind a cf:// name (T-300): the layer's heartbeat
        // finds a dead link, as on node:// (T-154). An interval that the user
        // set stays, with one warning where resolve could not know (T-703).
        layer_alive::apply(reached.layer.is_some(), resolved, &mut opts.keepalive_interval, tried == 1, log);
        let near = reached.relay.clone().map(|status| near_cap::spawn(status, log.clone()));
        // The relay's idle cut alone: a road of the resumable layer has none.
        let idle = reached
            .relay
            .clone()
            .filter(|_| reached.layer.is_none())
            .and_then(|status| idle_warn::spawn(status, opts.silence.clone(), opts.idle_lead, log.clone()));
        // A rank in the session's background, with RelayRank auto (T-608).
        let ranker = crate::relay_rank_auto::spawn(&resolved.transport, reached.relay.is_some());
        opts.window_cap = window::road(&resolved.transport, &reached).cap();
        podssh_relay::context::tell_idle(); // the relay's idle limit, for an idle cut's words (T-814)
        let mut outcome = podssh_ssh::run::run_outcome(reached.stream, &opts, reached.relay, log.clone()).await;
        for watch in [near, idle, ranker].into_iter().flatten() {
            watch.abort();
        }
        // The layer's CLOSE, and the line of its failure, before the exit.
        let layered = reached.layer.is_some();
        transport::settle(reached.layer).await;
        crate::layer_told::once(&mut outcome.lines, layered);
        // An IPv6 target that the relay opened, then closed before any byte:
        // the direct road once, in place of another try of the relay (T-253).
        if outcome.retry.is_some() && transport::ipv6_unreached(resolved, relay.as_ref()) {
            // The record says how the relay's session ended, as the road after it has no relay.
            if let Some(end) = relay.as_ref().and_then(podssh_ssh::RelayStatus::get) {
                podssh_ssh::outcome::relay_end(&end);
            }
            unreached = Some(transport::NotReached { lines: outcome.lines, code: outcome.code });
            continue;
        }
        let how = match outcome.retry {
            Some(Retry::NextHost) if tried < most && skip + 1 < hosts => {
                skip += 1;
                "on the next relay host"
            }
            Some(Retry::Again) if tried < most.max(2) && !again => {
                again = true;
                "once more"
            }
            _ => {
                for line in &outcome.lines {
                    log.error(line);
                }
                // A proxy that took the CONNECT and sent nothing back (T-317).
                if outcome.code != 0 {
                    if let Some(cause) = direct_proxy.as_ref().and_then(|d| d.cause(&target)) {
                        log.error(&cause);
                    }
                }
                return (outcome.code, relay);
            }
        };
        let wait = podssh_relay::open::backoff(tried as u32);
        let why = outcome.lines.first().map_or("the relay dropped the session", String::as_str);
        log.info(&format!("{why}; nothing had reached {target}, so podssh tries {how} in {:.1} s", wait.as_secs_f32()));
        tokio::time::sleep(wait).await;
        // A person may not be there to answer a prompt again.
        opts.set_batch_mode();
    }
}
