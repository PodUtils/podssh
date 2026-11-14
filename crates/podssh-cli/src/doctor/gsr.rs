//! The GSRN road, in a build with the feature `gsr` (T-707): whether this
//! binary's TLS with SRP works (`podssh_gsr::check_tls`, with no
//! connection), and, once the user named the road's secret with
//! `PODSSH_GSR_SECRET_FILE`, the relay's host that the secret gives and one
//! round trip of the control protocol there, by a secret that nobody holds
//! on the same shard, so that no node of the user's is disturbed. With
//! `--full`, one registration with no traffic but the relay's pings is
//! held for 20 s, past the 15 s at which a proxy was seen to cut an idle
//! CONNECT tunnel: whether the road's keepalive keeps a node registered
//! here. No byte goes to the relay unless the user named a secret.

use std::time::{Duration, Instant};

use podssh_ws::ProxyChoice;

use super::Report;

/// The bound of the round trip.
const LIMIT: Duration = Duration::from_secs(15);
/// How long the idle registration of `--full` is held.
const HOLD: Duration = Duration::from_secs(20);

pub(super) async fn check(report: &mut Report<'_>, full: bool) {
    let settings = match podssh_gsr::settings() {
        Ok(settings) => settings,
        Err(why) => return report.fail("gsr", format!("the relay's facts: {why}")),
    };
    match podssh_gsr::check_tls(&settings) {
        Ok(version) => report.ok("gsr tls", format!("TLS with SRP builds on both sides ({version})")),
        Err(why) => return report.fail("gsr tls", why),
    }
    // A bad file is said here as the road would say it (78), never its text.
    let secret = match crate::gsr::secret(None) {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            let why =
                format!("not tried: {} names no secret, and no byte goes to the relay unasked", crate::gsr::SECRET_ENV);
            return report.unknown("gsr", why);
        }
        Err(refusal) => return report.fail("gsr", refusal.message),
    };
    if let Err(why) = podssh_gsr::check_secret(&settings, secret.expose()) {
        return report.fail("gsr", format!("the secret: {why}"));
    }
    if podssh_relay::open::offline() {
        return report.unknown("gsr", "not attempted: PODSSH_OFFLINE is set");
    }
    let host = podssh_gsr::host_of(&settings, secret.expose());
    let dial = podssh_gsr::dialer(&ProxyChoice::FromEnvironment);
    match podssh_gsr::round_trip(&*dial, &settings, Some(secret.expose()), LIMIT).await {
        Ok(took) => report.ok("gsr", format!("the relay {host} answered in {} ms", took.as_millis())),
        Err(why) => return report.fail("gsr", format!("the relay {host}: {why}")),
    }
    if !full {
        let why =
            format!("not tried: podssh doctor --full holds a registration with no traffic for {} s", HOLD.as_secs());
        return report.unknown("gsr idle", why);
    }
    let started = Instant::now();
    match podssh_gsr::idle_holds(&*dial, &settings, HOLD).await {
        Ok(()) => report.ok(
            "gsr idle",
            format!("a registration with the relay's pings alone lived {} s", started.elapsed().as_secs()),
        ),
        Err(why) => report.fail(
            "gsr idle",
            format!("a registration with the relay's pings alone ended after {} s: {why}", started.elapsed().as_secs()),
        ),
    }
}
