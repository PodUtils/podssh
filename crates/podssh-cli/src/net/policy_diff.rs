//! What a policy changes, and what it is expected to let (T-749, the block
//! "tunnet 1" of PodUtils/podnet#438): each question that a net can ask,
//! from each member to each node, route of a share, exit, relay role, the
//! first address of each range of routes, and `relay:*`, answered by
//! `policy::check`, the one evaluator that each node uses for each session,
//! under two documents; and a file of cases, each one allowed or refused.
//! The diff is by the answers, not the text, so a policy that is only
//! reordered changes nothing. A range of routes is asked by its first
//! address alone, so a rule that splits a range is not seen there; the
//! report says so.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use serde_json::Value;

use super::doc::{Doc, Member};
use super::policy::{self, Want};

/// What a question asks to reach.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Node(String, Option<String>),
    Exit(String),
    Relay(Option<String>),
    Addr(IpAddr),
}

impl Target {
    pub fn want(&self) -> Want<'_> {
        match self {
            Target::Node(node, route) => Want::Node { node, route: route.as_deref() },
            Target::Exit(node) => Want::Exit(node),
            Target::Relay(node) => Want::Relay(node.as_deref()),
            Target::Addr(addr) => Want::Addr(*addr),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.want())
    }
}

/// The first address of a range of routes as the owner wrote it.
fn first_address(range: &str) -> Option<IpAddr> {
    range.split('/').next()?.trim().parse().ok()
}

/// What can be reached of `to`.
fn targets_of(to: &Member) -> Vec<Target> {
    let mut out = vec![Target::Node(to.name.clone(), None)];
    out.extend(to.shares.iter().map(|share| Target::Node(to.name.clone(), Some(share.clone()))));
    if to.has_role("exit") {
        out.push(Target::Exit(to.name.clone()));
    }
    if to.has_role("relay") {
        out.push(Target::Relay(Some(to.name.clone())));
    }
    out.extend(to.routes.iter().filter_map(|range| first_address(range)).map(Target::Addr));
    out
}

/// Each question of the members of `docs`, each once: from each member to
/// each target of each member, and to `relay:*`.
pub fn questions(docs: &[&Doc]) -> Vec<(String, Target)> {
    let mut members: Vec<&Member> = Vec::new();
    for doc in docs {
        for member in &doc.members {
            if !members.iter().any(|m| m.name == member.name) {
                members.push(member);
            }
        }
    }
    let mut out = BTreeSet::new();
    for from in &members {
        for to in &members {
            for target in targets_of(to) {
                out.insert((from.name.clone(), target));
            }
        }
        out.insert((from.name.clone(), Target::Relay(None)));
    }
    out.into_iter().collect()
}

/// One answer that changed: from, to, and the rule that lets it now
/// (widened) or let it before (narrowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub from: String,
    pub to: Target,
    pub why: String,
}

/// What a new document changes against the old one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub widened: Vec<Change>,
    pub narrowed: Vec<Change>,
    /// The questions of a member that the old document does not hold, which
    /// are no change of the policy.
    pub new_members: usize,
}

/// Each question whose answer differs between `old` and `new`.
pub fn diff(old: &Doc, new: &Doc) -> Diff {
    let mut out = Diff::default();
    for (from, to) in questions(&[old, new]) {
        let member = |doc: &Doc| doc.member(&from).cloned();
        let names_new = |doc: &Doc| match &to {
            Target::Node(node, _) | Target::Exit(node) | Target::Relay(Some(node)) => doc.member(node).is_none(),
            _ => false,
        };
        let (Some(was), Some(now)) = (member(old), member(new)) else {
            out.new_members += 1;
            continue;
        };
        if names_new(old) {
            out.new_members += 1;
            continue;
        }
        let before = policy::check(old, &was, to.want());
        let after = policy::check(new, &now, to.want());
        match (before, after) {
            (Err(_), Ok(why)) => out.widened.push(Change { from, to, why }),
            (Ok(why), Err(_)) => out.narrowed.push(Change { from, to, why }),
            _ => {}
        }
    }
    out
}

impl Diff {
    /// The lines of the report: the widened ones, the narrowed ones, at most
    /// `most` of all, then the counts.
    pub fn lines(&self, most: usize) -> Vec<String> {
        let mut out = Vec::new();
        let widened = self.widened.iter().map(|c| format!("+ {} -> {} ({})", c.from, c.to, c.why));
        let narrowed = self.narrowed.iter().map(|c| format!("- {} -> {} (was {})", c.from, c.to, c.why));
        let all: Vec<String> = widened.chain(narrowed).collect();
        let left = all.len().saturating_sub(most);
        out.extend(all.into_iter().take(most));
        if left > 0 {
            out.push(format!("... and {left} more"));
        }
        out.push(format!(
            "{} widened, {} narrowed; {} questions of a new member are no change; a range of routes is asked by \
             its first address alone",
            self.widened.len(),
            self.narrowed.len(),
            self.new_members
        ));
        out
    }
}

/// One case of an expectation file: `from`, `to` in the words of `policy
/// check`, `want` `allow` or `refuse`, and the owner's `note`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub from: String,
    pub to: String,
    pub allow: bool,
    pub note: Option<String>,
}

/// The cases of an expectation file: `{"expect": [CASE, ...]}`.
pub fn cases(value: &Value) -> Result<Vec<Case>, String> {
    let list = value.get("expect").and_then(Value::as_array).ok_or("no \"expect\": a list of cases")?;
    let text = |case: &Value, n: usize, field: &str| {
        case.get(field).and_then(Value::as_str).map(str::to_string).ok_or(format!("case {n} has no {field:?} text"))
    };
    let mut out = Vec::new();
    for (i, case) in list.iter().enumerate() {
        let n = i + 1;
        let allow = match text(case, n, "want")?.as_str() {
            "allow" => true,
            "refuse" => false,
            other => return Err(format!("case {n}: want {other:?}: allow or refuse")),
        };
        let note = case.get("note").and_then(Value::as_str).map(str::to_string);
        out.push(Case { from: text(case, n, "from")?, to: text(case, n, "to")?, allow, note });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "policy_diff_tests.rs"]
mod tests;
