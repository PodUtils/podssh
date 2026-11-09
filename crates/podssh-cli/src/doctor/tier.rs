//! `podssh doctor --tier` (T-706): one verdict of what this host allows, and
//! what each closed capability closes. Five categories, each `ok`, `closed`
//! or `????`. The probes are the ones of `host.rs` and `names.rs`, run once,
//! and their facts come here as values: this file only decides, from facts,
//! and says it. A capability that could not be read is `????`, never `ok`; a
//! closed capability is a fact, not a failure, so it never fails the run.
//!
//! The closed features come from one table, [`CLOSES`], in code. Its test
//! checks each named verb and flag against the flag table, so a rename or a
//! removal cannot leave a stale row.

// The probes that fill the facts are Unix's; elsewhere each fact stays unread.
#![cfg_attr(not(unix), allow(dead_code))]

use super::net::PROBE;
use super::report::Line;
use super::Report;

/// The five categories, in the order that they are said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rung {
    Identity,
    Exec,
    Terminal,
    State,
    Resolver,
}

impl Rung {
    #[cfg(test)]
    pub(super) const ALL: [Rung; 5] = [Rung::Identity, Rung::Exec, Rung::Terminal, Rung::State, Rung::Resolver];

    pub(super) fn word(self) -> &'static str {
        match self {
            Rung::Identity => "identity",
            Rung::Exec => "exec",
            Rung::Terminal => "terminal",
            Rung::State => "state",
            Rung::Resolver => "resolver",
        }
    }
}

/// Why a category is closed; a category can have more than one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Each reason is a capability that the host lacks, so each says `No`.
#[allow(clippy::enum_variant_names)]
pub(super) enum Reason {
    NoUserName,
    NoBindCapability,
    NoExecDir,
    NoPty,
    NoStateDir,
    NoResolver,
}

impl Reason {
    #[cfg(test)]
    pub(super) const ALL: [Reason; 6] = [
        Reason::NoUserName,
        Reason::NoBindCapability,
        Reason::NoExecDir,
        Reason::NoPty,
        Reason::NoStateDir,
        Reason::NoResolver,
    ];
}

/// A feature of podssh: a verb, and a flag of it when the feature is the
/// flag's, with the words for what is closed.
pub(super) struct Feature {
    pub verb: &'static str,
    pub flag: Option<&'static str>,
    pub what: &'static str,
}

const fn feature(verb: &'static str, flag: Option<&'static str>, what: &'static str) -> Feature {
    Feature { verb, flag, what }
}

/// What each closed reason closes. Not the serve side's tty routes: those
/// are T-248's, and join the `NoPty` row when they exist.
pub(super) const CLOSES: &[(Reason, &[Feature])] = &[
    (Reason::NoUserName, &[feature("ssh", None, "a destination with no user@host, -l or PODSSH_USER")]),
    (
        Reason::NoBindCapability,
        &[
            feature("relay", Some("listen"), "a listener on a port below 1024"),
            feature("exit", Some("listen"), "a local proxy on a port below 1024"),
        ],
    ),
    (
        Reason::NoExecDir,
        &[
            feature("session", Some("detach"), "podssh started again from a file"),
            feature("node", Some("detach"), "podssh started again from a file"),
            feature("pipe", Some("detach"), "podssh started again from a file"),
            feature("update", None, "the new binary run from a staged file"),
        ],
    ),
    (
        Reason::NoPty,
        &[
            feature("session", None, "a program on a terminal of its own"),
            feature("node", Some("sshd"), "the logins of an sshd on a pty"),
        ],
    ),
    (
        Reason::NoStateDir,
        &[
            feature("session", None, "its socket and its record in the cache"),
            feature("detached", None, "the record of the runs of --detach"),
        ],
    ),
    (
        Reason::NoResolver,
        &[
            feature("ssh", None, "the relay's name"),
            feature("proxy", None, "the relay's name"),
            feature("pipe", None, "the relay's name"),
        ],
    ),
];

/// The user, as the database and the environment give it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Name {
    Entry(String),
    /// No database entry; the name is that of a variable (`USER=x`).
    Variable(String),
    Root,
    /// No entry, no variable, not uid 0.
    Missing(u32),
    Unread(String),
    #[default]
    NotProbed,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Pty {
    Allocates(String),
    Closed(String),
    #[default]
    NotProbed,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum State {
    Writes(String),
    Closed(String),
    #[default]
    NotProbed,
}

/// What the directories that were tried for a program said, counted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Floor {
    ran_from: Option<String>,
    refused: usize,
    untried: usize,
}

impl Floor {
    pub(super) fn ran(&mut self, dir: String) {
        self.ran_from.get_or_insert(dir);
    }

    /// A directory that cannot be written, or that runs nothing.
    pub(super) fn closed(&mut self) {
        self.refused += 1;
    }

    /// A directory whose try did not end in an answer.
    pub(super) fn unknown(&mut self) {
        self.untried += 1;
    }
}

/// The facts of the probes of `host.rs`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Facts {
    pub name: Name,
    /// Whether the capability that binds a low port is held; None: unread.
    pub bind: Option<bool>,
    pub floor: Floor,
    pub pty: Pty,
    pub state: State,
}

/// The class of the way that names resolve, from the order of the dialer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Resolver {
    Proxy,
    Pins(usize),
    System(String),
    Cache(usize),
    Doh(String),
    Unresolved(String),
    Unknown(String),
}

/// One category's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Call {
    Ok(String),
    Closed(Vec<Reason>, String),
    Unknown(String),
}

pub(super) fn identity(name: &Name, bind: Option<bool>) -> Call {
    let (mut reasons, mut notes, mut unread) = (Vec::new(), Vec::new(), false);
    match name {
        Name::Entry(n) => notes.push(format!("user '{n}'")),
        Name::Variable(v) => notes.push(format!("no database entry; the name is from {v}")),
        Name::Root => notes.push("uid 0, with no database entry".to_string()),
        Name::Missing(uid) => {
            reasons.push(Reason::NoUserName);
            notes.push(format!("uid {uid} has no database entry and no name in the environment"));
        }
        Name::Unread(why) => {
            unread = true;
            notes.push(why.clone());
        }
        Name::NotProbed => {
            unread = true;
            notes.push("the user was not probed on this system".to_string());
        }
    }
    match bind {
        Some(true) => notes.push("cap_net_bind_service is held".to_string()),
        Some(false) => {
            reasons.push(Reason::NoBindCapability);
            notes.push("cap_net_bind_service is not held".to_string());
        }
        None => {
            unread = true;
            notes.push("the capability sets could not be read".to_string());
        }
    }
    let said = notes.join("; ");
    match (reasons.is_empty(), unread) {
        (false, _) => Call::Closed(reasons, said),
        (true, true) => Call::Unknown(said),
        (true, false) => Call::Ok(said),
    }
}

pub(super) fn exec(floor: &Floor) -> Call {
    if let Some(dir) = &floor.ran_from {
        return Call::Ok(format!("a copy of podssh ran from {dir}"));
    }
    if floor.untried > 0 || floor.refused == 0 {
        let tried = floor.refused + floor.untried;
        return Call::Unknown(format!("no directory ran a copy of podssh; {tried} could not be tried to the end"));
    }
    Call::Closed(vec![Reason::NoExecDir], format!("none of {} directories can be written and run from", floor.refused))
}

pub(super) fn terminal(pty: &Pty) -> Call {
    match pty {
        Pty::Allocates(name) => Call::Ok(format!("a pty can be allocated ({name})")),
        Pty::Closed(why) => Call::Closed(vec![Reason::NoPty], why.clone()),
        Pty::NotProbed => Call::Unknown("no pty probe on this system".to_string()),
    }
}

pub(super) fn state(state: &State) -> Call {
    match state {
        State::Writes(dir) => Call::Ok(format!("{dir} can be written")),
        State::Closed(why) => Call::Closed(vec![Reason::NoStateDir], why.clone()),
        State::NotProbed => Call::Unknown("no cache directory was probed".to_string()),
    }
}

pub(super) fn resolver(class: &Resolver) -> Call {
    match class {
        Resolver::Proxy => Call::Ok("proxy: the proxy is given the names and resolves them".to_string()),
        Resolver::Pins(n) => Call::Ok(format!("pins: {n} pinned address(es) are used before any resolver")),
        Resolver::System(ips) => Call::Ok(format!("system: the resolver of this host answers ({ips})")),
        Resolver::Cache(n) => Call::Ok(format!("cache: the system resolver fails; {n} fresh address(es) are kept")),
        Resolver::Doh(ip) => Call::Ok(format!("DoH: the system resolver fails; {ip} answers over HTTPS")),
        Resolver::Unresolved(why) => Call::Closed(vec![Reason::NoResolver], format!("none: {why}")),
        Resolver::Unknown(why) => Call::Unknown(why.clone()),
    }
}

/// The five verdicts, in order.
pub(super) fn compose(facts: &Facts, class: &Resolver) -> Vec<(Rung, Call)> {
    vec![
        (Rung::Identity, identity(&facts.name, facts.bind)),
        (Rung::Exec, exec(&facts.floor)),
        (Rung::Terminal, terminal(&facts.pty)),
        (Rung::State, state(&facts.state)),
        (Rung::Resolver, resolver(class)),
    ]
}

/// The features that `reasons` close, as words.
pub(super) fn closed_words(reasons: &[Reason]) -> String {
    let mut said = Vec::new();
    for (reason, features) in CLOSES {
        if !reasons.contains(reason) {
            continue;
        }
        for f in *features {
            let flag = f.flag.map(|l| format!(" --{l}")).unwrap_or_default();
            said.push(format!("podssh {}{flag} ({})", f.verb, f.what));
        }
    }
    said.join("; ")
}

impl Report<'_> {
    /// A line of the tier: its label is one of `ok`, `closed` and `????`.
    /// Only `ok` and `????` are counted; a closed capability is no check.
    fn tier_line(&mut self, name: &str, call: &Call) {
        let (label, status, detail) = match call {
            Call::Ok(d) => {
                self.ok += 1;
                ("ok", "ok", d.clone())
            }
            Call::Unknown(d) => {
                self.unknown += 1;
                ("????", "unknown", d.clone())
            }
            Call::Closed(reasons, d) => {
                let features = closed_words(reasons);
                let then = match features.is_empty() {
                    true => String::new(),
                    false => format!("; unavailable because of this: {features}"),
                };
                ("closed", "closed", format!("{d}{then}"))
            }
        };
        let detail = podssh_ws::text::one_line(&detail);
        if !self.json {
            let _ = writeln!(self.out, "  {label:<6} {name:<10} {detail}");
            let _ = self.out.flush();
        }
        self.lines.push(Line { section: self.section.clone(), check: name.to_string(), status, detail, samples: None });
    }
}

/// The report of the five verdicts, and the sum line.
pub(super) fn show(report: &mut Report<'_>, calls: &[(Rung, Call)]) {
    report.section("tier");
    for (rung, call) in calls {
        report.tier_line(rung.word(), call);
    }
    let closed = calls.iter().filter(|(_, c)| matches!(c, Call::Closed(..))).count();
    let unknown = calls.iter().filter(|(_, c)| matches!(c, Call::Unknown(_))).count();
    let open = calls.len() - closed - unknown;
    let sum = format!("{open} of {} capabilities open, {closed} closed, {unknown} ????", calls.len());
    let call = match (closed, unknown) {
        (0, 0) => Call::Ok(sum),
        (0, _) => Call::Unknown(sum),
        _ => Call::Closed(Vec::new(), sum),
    };
    // The sum counts as nothing: it says the lines above it again.
    let (ok, no) = (report.ok, report.unknown);
    report.tier_line("verdict", &call);
    (report.ok, report.unknown) = (ok, no);
}

/// `--tier`: this host's lines were printed; add the resolver's class, and
/// the verdict, then end. Reads capability sets and tries what the lines did;
/// drops nothing, and fails only where a check did.
pub(super) fn only(mut report: Report<'_>, facts: &Facts, host: &str) -> i32 {
    let class = probe_resolver(host);
    let calls = compose(facts, &class);
    show(&mut report, &calls);
    report.finish()
}

/// The class of the dialer's order that resolves `host` here: a proxy that is
/// given the name, a pin, the system resolver, a fresh cached address, a
/// DNS-over-HTTPS resolver, or none.
fn probe_resolver(host: &str) -> Resolver {
    use podssh_ws::dial;
    match dial::proxy_from_env(host) {
        Err(why) => return Resolver::Unknown(format!("a proxy is set but cannot be used: {why}")),
        Ok(Some(_)) => return Resolver::Proxy,
        Ok(None) => {}
    }
    let pinned = podssh_ws::resolve::pinned(host);
    if !pinned.is_empty() {
        return Resolver::Pins(pinned.len());
    }
    if podssh_relay::open::offline() {
        return Resolver::Unknown("PODSSH_OFFLINE is set: no lookup was tried".to_string());
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => return Resolver::Unknown(format!("could not start the async runtime: {e}")),
    };
    let class = runtime.block_on(lookup(host));
    runtime.shutdown_background();
    class
}

async fn lookup(host: &str) -> Resolver {
    let failed = match super::names::system_lookup(host).await {
        Ok(ips) => return Resolver::System(ips),
        Err(e) => e,
    };
    let (fresh, _) = podssh_ws::resolve::split(&podssh_ws::resolve::remembered(host), crate::pairs::now_ms());
    if !fresh.is_empty() {
        return Resolver::Cache(fresh.len());
    }
    let mut missed = Vec::new();
    for resolver in &podssh_ws::resolve::doh_resolvers() {
        let deadline = tokio::time::Instant::now() + PROBE;
        match podssh_ws::resolve::doh_ask_kept(resolver, host, deadline).await {
            Ok(_) => return Resolver::Doh(resolver.ip.to_string()),
            // An answer: the name does not exist, and the resolver works.
            Err(e) if e.why.ends_with(podssh_ws::resolve::NXDOMAIN) => return Resolver::Doh(resolver.ip.to_string()),
            Err(e) => missed.push(e.why),
        }
    }
    let doh = missed.join("; ");
    let said = format!("the system resolver fails ({failed}), and no DNS-over-HTTPS resolver answered ({doh})");
    Resolver::Unresolved(said)
}

#[cfg(test)]
#[path = "tier_tests.rs"]
mod tests;
