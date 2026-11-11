//! The burst (T-747, the probe of PodUtils/podnet#438's block "satmux 7"):
//! [`K`] TLS handshakes with the relay host at once, and a control of the
//! same [`K`] one after another, in two rounds whose order is swapped
//! (burst, control, control, burst), so that neither arm owns a warm cache.
//! The other probes of `doctor` try one connection at a time, so a gateway
//! that resets what goes past a few open connections looks clean there,
//! and its user cannot tell that limit from a lossy path. Three verdicts:
//! no limit seen up to [`K`]; a limit, where the control passed and a burst
//! did not; or not shown to be a limit, where the control failed too (one
//! connection alone fails, as GitHub #99's name filter). Each failure is
//! classed by its kind (`Cut`), never by its words. The whole probe stays
//! within [`BUDGET`]; through a proxy it measures the proxy's limit, and
//! its line says so. It runs after the relay's own checks, in their part,
//! so that no other section of `doctor` opens a connection to the relay
//! beside it.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use podssh_relay::relay::RelayList;
use podssh_ws::{ConnectError, Cut, DialError, ProxyChoice, Trust, Verdict};
// tokio's clock, which a test can pause.
use tokio::time::Instant;

use super::Report;

/// The handshakes of each round: the donor's burst of six origins.
pub(super) const K: usize = 6;
/// The bound of the whole probe, as of a probe of `samples`.
pub(super) const BUDGET: Duration = Duration::from_secs(10);
/// The bound of one handshake.
const EACH: Duration = Duration::from_secs(8);
/// The control's spread, as `samples`'s.
const SPREAD: Duration = Duration::from_millis(125);

/// The kind of a handshake's failure.
pub(super) fn class_of(e: &ConnectError) -> &'static str {
    if matches!(e, ConnectError::Dial(DialError::ProxyRefused { .. })) {
        return "refused by the proxy";
    }
    match e.cut() {
        Some(Cut::Reset) => "reset",
        Some(Cut::TimedOut) => "timeout",
        Some(Cut::Refused) => "refused",
        Some(Cut::Closed) => "closed",
        _ => "other",
    }
}

/// One round: the handshakes that passed, each failure by its kind, and
/// whether the budget cut it short.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Round {
    pub ok: usize,
    pub failed: BTreeMap<&'static str, usize>,
    pub cut: bool,
}

impl Round {
    fn failures(&self) -> usize {
        self.failed.values().sum()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "ok": self.ok, "failed": self.failed, "cut": self.cut })
    }
}

/// What a handshake gave: passed, or the kind of its failure.
pub(super) type Outcome = Result<(), &'static str>;

/// [`K`] handshakes at once, each bounded by what is left before `until`.
pub(super) async fn burst<F, Fut>(until: Instant, shake: &F) -> Round
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let left = until.saturating_duration_since(Instant::now()).min(EACH);
    if left.is_zero() {
        return Round { cut: true, ..Round::default() };
    }
    let all = futures_util::future::join_all((0..K).map(|_| shake(left))).await;
    let mut round = Round::default();
    for outcome in all {
        tally(&mut round, outcome);
    }
    round
}

/// [`K`] handshakes one after another, [`SPREAD`] apart, each closed before
/// the next, bounded as [`burst`]'s.
pub(super) async fn control<F, Fut>(until: Instant, shake: &F) -> Round
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let mut round = Round::default();
    for i in 0..K {
        if i > 0 {
            tokio::time::sleep(SPREAD.min(until.saturating_duration_since(Instant::now()))).await;
        }
        let left = until.saturating_duration_since(Instant::now()).min(EACH);
        if left.is_zero() {
            round.cut = true;
            break;
        }
        tally(&mut round, shake(left).await);
    }
    round
}

fn tally(round: &mut Round, outcome: Outcome) {
    match outcome {
        Ok(()) => round.ok += 1,
        Err(class) => *round.failed.entry(class).or_insert(0) += 1,
    }
}

/// The four rounds, in their order: burst, control, control, burst.
pub(super) struct Rounds {
    pub bursts: [Round; 2],
    pub controls: [Round; 2],
}

/// Run the four rounds within [`BUDGET`].
pub(super) async fn rounds<F, Fut>(shake: F) -> Rounds
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let until = Instant::now() + BUDGET;
    // A pause before each round, so that the connections of what came before
    // it (the relay's checks, the round before) have closed: a gateway counts
    // a connection until it sees it end.
    let pause = || tokio::time::sleep(SPREAD.min(until.saturating_duration_since(Instant::now())));
    pause().await;
    let first = burst(until, &shake).await;
    pause().await;
    let one = control(until, &shake).await;
    pause().await;
    let two = control(until, &shake).await;
    pause().await;
    let last = burst(until, &shake).await;
    Rounds { bursts: [first, last], controls: [one, two] }
}

/// The failures of both rounds of an arm, by kind, in words.
fn classes(rounds: &[Round; 2]) -> String {
    let mut all: BTreeMap<&str, usize> = BTreeMap::new();
    for round in rounds {
        for (class, n) in &round.failed {
            *all.entry(class).or_insert(0) += n;
        }
    }
    let words: Vec<String> = all.iter().map(|(class, n)| format!("{n} {class}")).collect();
    words.join(", ")
}

/// The verdict of the rounds: a burst arm fails where either of its rounds
/// has a failure, and its count is the worse round's.
pub(super) fn verdict(rounds: &Rounds) -> Verdict {
    let Rounds { bursts, controls } = rounds;
    let cut = bursts.iter().chain(controls).any(|r| r.cut);
    let cut_words = if cut { format!("; the rounds were cut at {} s", BUDGET.as_secs()) } else { String::new() };
    let alone_failed = controls.iter().map(Round::failures).max().unwrap_or(0);
    if alone_failed > 0 {
        let why = format!(
            "not shown to be a concurrency limit: {alone_failed}/{K} handshakes fail even alone ({}); see the relay's \
             lines above{cut_words}",
            classes(controls)
        );
        return Verdict::Unknown { why };
    }
    let together = bursts.iter().map(|r| r.ok).min().unwrap_or(0);
    let burst_failed = bursts.iter().any(|r| r.failures() > 0);
    if !burst_failed && !cut {
        let detail =
            format!("no concurrency limit seen up to {K}: {K}/{K} together twice, {K}/{K} one at a time twice");
        return Verdict::Ok { detail };
    }
    if !burst_failed {
        return Verdict::Unknown { why: format!("the rounds were not all made within {} s", BUDGET.as_secs()) };
    }
    let detail = format!(
        "concurrency limit: {together}/{K} handshakes succeed together, {K}/{K} one at a time; fails as {}{cut_words}: \
         fewer sessions at once may hold where more break",
        classes(bursts)
    );
    Verdict::Failed { detail }
}

/// The numbers of `--json`.
pub(super) fn json(rounds: &Rounds) -> serde_json::Value {
    let Rounds { bursts, controls } = rounds;
    serde_json::json!({
        "k": K,
        "burst_ok": bursts.iter().map(|r| r.ok).min().unwrap_or(0),
        "control_ok": controls.iter().map(|r| r.ok).min().unwrap_or(0),
        "bursts": [bursts[0].json(), bursts[1].json()],
        "controls": [controls[0].json(), controls[1].json()],
    })
}

/// The section `burst`: the rounds against the first relay host, through the
/// proxy of the environment.
pub(super) async fn check(report: &mut Report<'_>, relays: &RelayList, trust: &Trust) {
    report.section("burst");
    let primary = relays.primary();
    let (host, port) = (primary.host.as_str(), primary.port);
    let proxied = matches!(podssh_ws::dial::proxy_from_env(host), Ok(Some(_)));
    let shake = |bound: Duration| async move {
        let opened = podssh_ws::client::open_tls(host, port, host, trust, &ProxyChoice::FromEnvironment, bound).await;
        opened.map(drop).map_err(|e| class_of(&e))
    };
    let rounds = rounds(shake).await;
    let mut verdict = verdict(&rounds);
    let target = podssh_ws::dial::authority(host, port);
    let through = match proxied {
        true => " through the proxy, so it measures the proxy's limit",
        false => "",
    };
    match &mut verdict {
        Verdict::Ok { detail } | Verdict::Failed { detail } => *detail = format!("{target}{through}: {detail}"),
        Verdict::Unknown { why } => *why = format!("{target}{through}: {why}"),
    }
    report.line("concurrency", verdict);
    if let Some(line) = report.lines.last_mut() {
        line.samples = Some(json(&rounds));
    }
}

#[cfg(test)]
#[path = "burst_tests.rs"]
mod tests;
