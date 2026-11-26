//! `podssh ping --nodes NAME,...` and `podssh ping --net`: the roads of each
//! node of a list, measured as `ping node://NAME` measures one, so that a
//! monitor of a fleet reads one object in one shape. At most `--parallel`
//! nodes are measured at once, each within `--timeout`, and the run within
//! its own limit. A node that fails says why beside the others; none of them
//! waits for it. Each road that starts opens its one connection for a short
//! time and ends its link before a byte is sent on it, as for one node.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{self, StreamExt};
use podssh_ssh::Log;
use serde_json::{json, Value};

use super::PingArgs;
use crate::exitmap::sysexits::{EX_TEMPFAIL, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;
use crate::ssh::resolve::{self, Env, Resolved};
use crate::ssh::roads::probe::Measures;

/// The default and the most nodes measured at once.
const PARALLEL: usize = 8;
const MAX_PARALLEL: usize = 64;
/// The most nodes of one run: the most members of a net.
const MOST_NODES: usize = 256;
/// The bound of each node with no `--timeout`: the measure's own bound,
/// and time for its links to close.
const NODE_LIMIT: Duration = Duration::from_secs(60);

/// What one node gave: its measures, or why it has none, with its code.
struct Outcome {
    shown: String,
    measures: Option<Measures>,
    code: i32,
    error: Option<String>,
}

impl Outcome {
    /// A node that was not measured; a refusal that names the node already
    /// is said without that name, which the line's own prefix gives (T-1028).
    fn failed(shown: String, code: i32, error: String) -> Outcome {
        let error = crate::each::unlabeled(&shown, &error).to_string();
        Outcome { shown, measures: None, code, error: Some(error) }
    }
}

/// The flag of a list of nodes given with no list: `--parallel` and
/// `--timeout` belong to `--nodes` and `--net`.
pub(super) fn stray(args: &PingArgs) -> Option<&'static str> {
    match (&args.parallel, &args.timeout) {
        (Some(_), _) => Some("--parallel"),
        (None, Some(_)) => Some("--timeout"),
        (None, None) => None,
    }
}

/// `podssh ping --nodes` or `--net`: 0 when each node answered on a road, 1
/// when some did not, 69 when none did or with `PODSSH_OFFLINE`; 64 for a bad
/// flag and 78 for a net that cannot be read, before anything connects.
pub(super) fn run(args: &PingArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (names, parallel, limit) = match plan(args) {
        Ok(plan) => plan,
        Err(refusal) => return refusal.report("ping", err),
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("ping", err);
    }
    // Each node is resolved as `ping node://NAME` resolves it, before
    // anything connects; a node that does not resolve has its refusal.
    let env = Env::from_process();
    let resolved: Vec<(String, Result<Resolved, Refusal>)> = names
        .iter()
        .map(|name| {
            let mut ssh = args.ssh.clone();
            ssh.destination = Some(format!("{}{name}", crate::ssh::node::SCHEME));
            (format!("{}{name}", crate::ssh::node::SCHEME), resolve::resolve_or_refuse(&ssh, &env))
        })
        .collect();
    if podssh_relay::open::offline() {
        let _ = writeln!(err, "podssh ping: {}", podssh_relay::open::offline_line());
        return EX_UNAVAILABLE;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh ping: could not start the async runtime: {}", podssh_ws::text::said(&e));
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    let deadline = Instant::now() + super::RUN_LIMIT;
    // One thread: a node's record of its road is written whole before the
    // next node's, so that `status --net` loses none.
    let each = resolved
        .iter()
        .enumerate()
        .map(|(at, (shown, resolved))| async move { (at, one(shown, resolved, limit, deadline).await) });
    let measuring = stream::iter(each).buffer_unordered(parallel).collect::<Vec<(usize, Outcome)>>();
    let mut outcomes = runtime.block_on(measuring);
    // A road's dialer may have left a task behind; the measures are done.
    runtime.shutdown_background();
    outcomes.sort_by_key(|(at, _)| *at);
    let outcomes: Vec<Outcome> = outcomes.into_iter().map(|(_, outcome)| outcome).collect();
    let code = run_code(&outcomes);
    if args.json {
        let _ = writeln!(out, "{}", json_of(&outcomes, code));
    } else {
        for line in lines(&outcomes) {
            let _ = writeln!(out, "{line}");
        }
    }
    let _ = out.flush();
    code
}

/// The nodes, the most at once and each one's bound, from the flags; each
/// fault is refused before anything connects.
fn plan(args: &PingArgs) -> Result<(Vec<String>, usize, Duration), Refusal> {
    if args.nodes.is_some() && args.net {
        return Err(Refusal::usage("--nodes and --net are two lists: give one"));
    }
    if let Some(text) = &args.ssh.destination {
        return Err(Refusal::usage(format!("{text}: --nodes and --net take no destination")));
    }
    let host_flags = [
        (args.size.is_some(), "--size"),
        (args.count.is_some(), "--count"),
        (args.target.is_some(), "--target"),
        (args.under_load, "--under-load"),
        (args.connect_runs.is_some(), "--connect-runs"),
    ];
    if let Some((_, flag)) = host_flags.iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!("{flag} is a host's; the roads of each node of a list race once")));
    }
    let parallel = match args.parallel.as_deref() {
        None => PARALLEL,
        Some(text) => match text.parse::<usize>() {
            Ok(n) if (1..=MAX_PARALLEL).contains(&n) => n,
            _ => return Err(Refusal::usage(format!("--parallel {text}: from 1 to {MAX_PARALLEL}"))),
        },
    };
    let limit = node_limit(args.timeout.as_deref(), |name| std::env::var(name).ok())?;
    let names = match &args.nodes {
        Some(text) => listed(text)?,
        None => of_net()?,
    };
    Ok((names, parallel, limit))
}

/// Each node's bound: `--timeout`, else `PODSSH_TIMEOUT`, else
/// [`NODE_LIMIT`]; never past the run's own limit.
fn node_limit(flag: Option<&str>, var: impl Fn(&str) -> Option<String>) -> Result<Duration, Refusal> {
    let given = crate::non_interactive::optional_timeout(flag, var).map_err(|refusal| {
        // Its words name podssh already; `report` names the command.
        let message = refusal.message.trim_start_matches("podssh: ").to_string();
        Refusal { message, code: refusal.fault.code() }
    })?;
    match given {
        Some(limit) if limit > super::RUN_LIMIT => {
            let most = super::RUN_LIMIT.as_secs();
            Err(Refusal::usage(format!("--timeout: at most {most} s, the limit of the whole run")))
        }
        Some(limit) => Ok(limit),
        None => Ok(NODE_LIMIT),
    }
}

/// The names of `--nodes`: `NAME` or `node://NAME`, split at commas, each
/// once in the order given.
fn listed(text: &str) -> Result<Vec<String>, Refusal> {
    let mut names: Vec<String> = Vec::new();
    for word in text.split(',').map(str::trim) {
        let name = word.strip_prefix(crate::ssh::node::SCHEME).unwrap_or(word);
        if name.is_empty() {
            return Err(Refusal::usage(format!("--nodes {text}: a name is empty")));
        }
        if !names.iter().any(|kept| kept == name) {
            names.push(name.to_string());
        }
    }
    if names.len() > MOST_NODES {
        return Err(Refusal::usage(format!("--nodes: {} names, more than {MOST_NODES}", names.len())));
    }
    Ok(names)
}

/// The members of the net held with the role `node`, in its order.
fn of_net() -> Result<Vec<String>, Refusal> {
    let held = crate::net::store::held().map_err(|why| Refusal::config(format!("--net: {why}")))?;
    let Some(held) = held else {
        return Err(Refusal::config("--net: no net is held here; podssh net take FILE takes one"));
    };
    let doc = &held.signed.doc;
    let names: Vec<String> = doc.members.iter().filter(|m| m.has_role("node")).map(|m| m.name.clone()).collect();
    if names.is_empty() {
        return Err(Refusal::config(format!("--net: the net {} has no member with the role node", doc.name)));
    }
    Ok(names)
}

/// The measure of one node, within `limit` and the run's `deadline`.
async fn one(shown: &str, resolved: &Result<Resolved, Refusal>, limit: Duration, deadline: Instant) -> Outcome {
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(refusal) => return Outcome::failed(shown.to_string(), refusal.code, refusal.message.clone()),
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        let why = format!("not measured: the run passed its limit of {} s", super::RUN_LIMIT.as_secs());
        return Outcome::failed(shown.to_string(), EX_TEMPFAIL, why);
    }
    let log = Arc::new(Log::new(resolved.options.log_level));
    let measuring = crate::ssh::node_roads::measure(&resolved.transport, &log);
    match tokio::time::timeout(limit.min(left), measuring).await {
        Ok(Ok(measures)) => {
            let code = if measures.won.is_some() { 0 } else { EX_UNAVAILABLE };
            let error = measures.won.is_none().then(|| measures.why_none());
            Outcome { shown: shown.to_string(), measures: Some(measures), code, error }
        }
        Ok(Err(not)) => {
            let why = super::joined(not.lines.iter().flat_map(|l| l.lines()));
            Outcome::failed(shown.to_string(), not.code, why)
        }
        Err(_) => {
            let why = format!("no road answered within {:.1} s", limit.min(left).as_secs_f64());
            Outcome::failed(shown.to_string(), EX_TEMPFAIL, why)
        }
    }
}

/// 0 when each node answered, 69 when none did, else 1.
fn run_code(outcomes: &[Outcome]) -> i32 {
    let answered = outcomes.iter().filter(|outcome| outcome.code == 0).count();
    match answered {
        n if n == outcomes.len() => 0,
        0 => EX_UNAVAILABLE,
        _ => 1,
    }
}

/// The lines of each node in the order given, as `ping node://NAME` writes
/// them, then how many answered.
fn lines(outcomes: &[Outcome]) -> Vec<String> {
    let mut lines = Vec::new();
    for outcome in outcomes {
        match (&outcome.measures, &outcome.error) {
            (Some(measures), _) => lines.extend(super::node::lines(measures)),
            (None, Some(why)) => lines.push(format!("{}: {why}", outcome.shown)),
            (None, None) => {}
        }
    }
    let answered = outcomes.iter().filter(|outcome| outcome.code == 0).count();
    lines.push(format!("{answered} of {} nodes answered", outcomes.len()));
    lines
}

/// One JSON object: each node's object of `ping node://NAME --json`, with
/// its code and why it failed.
fn json_of(outcomes: &[Outcome], code: i32) -> Value {
    let node = |outcome: &Outcome| {
        let mut value = match &outcome.measures {
            Some(measures) => super::node::node_value(measures),
            None => json!({ "name": outcome.shown, "roads": [], "won": null, "won_ms": null }),
        };
        value["code"] = json!(outcome.code);
        value["error"] = json!(outcome.error);
        value
    };
    json!({
        "schema": 1,
        "podssh": crate::help::version(),
        "nodes": outcomes.iter().map(node).collect::<Vec<_>>(),
        "exit": code,
    })
}

#[cfg(test)]
#[path = "nodes_tests.rs"]
mod tests;
