//! `podssh net policy` (T-430): each end's `check FROM TO`, which says what
//! the rules of the document held let, with no connection, and `show`; the
//! owner's `set FILE` and `clear`, which sign a new document as each change
//! of the net does (`super::edit`).

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use podssh_relay::identity::KeyName;
use serde_json::{json, Map, Value};

use super::doc::{Doc, Member, MAX_DOC};
use super::policy::{self, Want};
use super::policy_diff;
use super::{held, summary, NetArgs};
use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// The words of `policy`, as a refusal names them.
const WORDS: &str = "check FROM TO, test FILE, diff POLICY, show, set FILE or clear";

/// The count of words after `net`, its verb included, and their shape.
pub(super) fn shape(args: &[String]) -> Result<(usize, &'static str), Refusal> {
    match args.first().map(String::as_str) {
        Some("check") => Ok((3, "policy check FROM TO")),
        Some("test") => Ok((2, "policy test FILE")),
        Some("diff") => Ok((2, "policy diff POLICY")),
        Some("set") => Ok((2, "policy set FILE")),
        Some("show") => Ok((1, "policy show")),
        Some("clear") => Ok((1, "policy clear")),
        Some(other) => Err(Refusal::usage(format!("podssh net policy {other:?}: {WORDS}"))),
        None => Err(Refusal::usage(format!("podssh net policy: {WORDS}"))),
    }
}

/// Whether the verb is the owner's, which signs a new document.
pub(super) fn signs(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("set" | "clear"))
}

/// Each end's verbs: `check` and `show`.
pub(super) fn run(args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let held = held()?;
    let _ = writeln!(err, "podssh net: {}", summary(&held));
    let doc = &held.signed.doc;
    match args.args[0].as_str() {
        "show" => Ok(show(doc, out, err)),
        "test" => test(doc, &read_json(&args.args[1])?, &args.args[1], out),
        "diff" => {
            let next = with_policy(doc, &args.args[1], err)?;
            let changed = policy_diff::diff(doc, &next);
            for line in changed.lines(usize::MAX) {
                let _ = writeln!(out, "{line}");
            }
            Ok(if args.exit_code && !changed.widened.is_empty() { sysexits::EX_DATAERR } else { 0 })
        }
        _ => check(doc, &args.args[1], &args.args[2], out),
    }
}

/// `show`: the policy as the document holds it, as a file that `set` takes
/// again.
fn show(doc: &Doc, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match doc.field(policy::FIELD) {
        Some(value) => {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(value).unwrap_or_default());
        }
        None => {
            let _ = writeln!(
                err,
                "podssh net: the net {} has no policy, so each member reaches each; its owner sets one with podssh \
                 net policy set FILE",
                doc.name
            );
        }
    }
    0
}

/// `check FROM TO`: one line on stdout, `allowed` or `refused`, a tab, and
/// the rule that lets it or why not; 0 or 77, as a node would let it in.
fn check(doc: &Doc, from: &str, to: &str, out: &mut dyn Write) -> Result<i32, Refusal> {
    let member = member_named(doc, from)?;
    let want = wanted(doc, to)?;
    let (word, why, code) = match policy::check(doc, member, want) {
        Ok(why) => ("allowed", why, 0),
        Err(why) => ("refused", why, sysexits::EX_NOPERM),
    };
    let _ = writeln!(out, "{word}\t{why}");
    Ok(code)
}

/// `test FILE`: each case of the expectation file through `policy::check`
/// of `doc`, one line each on `out`; 0, or 65 when one is false.
fn test(doc: &Doc, value: &Value, file: &str, out: &mut dyn Write) -> Result<i32, Refusal> {
    let failed = expectations(doc, value, file, out)?;
    Ok(if failed == 0 { 0 } else { sysexits::EX_DATAERR })
}

/// The cases of `value` against `doc`: how many are false.
fn expectations(doc: &Doc, value: &Value, file: &str, out: &mut dyn Write) -> Result<usize, Refusal> {
    let cases = policy_diff::cases(value).map_err(|why| data(format!("{file}: {why}")))?;
    let mut failed = 0;
    for case in &cases {
        let (member, want) = (member_named(doc, &case.from)?, wanted(doc, &case.to)?);
        let answer = policy::check(doc, member, want);
        let (word, why) = match &answer {
            Ok(why) => ("allow", why),
            Err(why) => ("refuse", why),
        };
        let ok = answer.is_ok() == case.allow;
        failed += usize::from(!ok);
        let expected = if case.allow { "allow" } else { "refuse" };
        let note = case.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
        let status = if ok { "ok" } else { "FAIL" };
        let _ =
            writeln!(out, "{status}\t{} -> {}: {expected}{note}, the policy says {word}: {why}", case.from, case.to);
    }
    Ok(failed)
}

/// The JSON of `file`, read as `set` reads its own.
fn read_json(file: &str) -> Result<Value, Refusal> {
    let path = Path::new(file);
    let no_input = |why: String| Refusal { message: why, code: sysexits::EX_NOINPUT };
    if !path.exists() {
        return Err(no_input(format!("{file}: no such file")));
    }
    let bytes = std::fs::read(path).map_err(|e| no_input(format!("{file}: {e}")))?;
    if bytes.len() > MAX_DOC {
        return Err(data(format!("{file} has {} bytes, more than a net's document holds", bytes.len())));
    }
    serde_json::from_slice(&bytes).map_err(|e| data(format!("{file} is not JSON: {e}")))
}

/// `doc` with the policy of `file`, checked as `set` checks it, unsigned.
fn with_policy(doc: &Doc, file: &str, err: &mut dyn Write) -> Result<Doc, Refusal> {
    let value = read_json(file)?;
    let (_, said) = policy::checked(&value, doc).map_err(|why| data(format!("{file}: {why}")))?;
    for line in said {
        let _ = writeln!(err, "podssh net: {file}: {line}");
    }
    let next = doc.next_whole(doc.issued, doc.expires, |whole| {
        whole.insert(policy::FIELD.into(), value);
        require(whole, true);
    });
    next.map_err(data)
}

/// FROM: a member's name, or its key or fingerprint, as a node's line names
/// the operator.
fn member_named<'a>(doc: &'a Doc, word: &str) -> Result<&'a Member, Refusal> {
    if let Some(member) = doc.member(word) {
        return Ok(member);
    }
    let print = KeyName::parse(word).map(|key| key.fingerprint());
    let by_key = print.and_then(|print| doc.members.iter().find(|m| m.key.fingerprint() == print));
    by_key.ok_or_else(|| Refusal::usage(format!("FROM {word}: the net {} has no member of that name or key", doc.name)))
}

/// TO: `NODE` (its target with no route), `NODE/ROUTE`, `exit:NODE`,
/// `relay:NODE` (the mint of its relay role, T-455), `relay:*` (a relay
/// role that is no member, as `podssh relay serve`'s), or an address of a
/// range of routes.
fn wanted<'a>(doc: &Doc, word: &'a str) -> Result<Want<'a>, Refusal> {
    if let Ok(addr) = word.parse::<IpAddr>() {
        return Ok(Want::Addr(addr));
    }
    let forms = "NODE, NODE/ROUTE, exit:NODE, relay:NODE, relay:* or an address";
    match word.strip_prefix("relay:") {
        Some("*") => return Ok(Want::Relay(None)),
        Some(node) if doc.member(node).is_some() => return Ok(Want::Relay(Some(node))),
        Some(node) => {
            let why = format!("TO {word}: the net {} has no member {node}; TO is {forms}", doc.name);
            return Err(Refusal::usage(why));
        }
        None => {}
    }
    let (node, route, exit) = match word.strip_prefix("exit:") {
        Some(node) => (node, None, true),
        None => match word.split_once('/') {
            Some((node, route)) => (node, Some(route), false),
            None => (word, None, false),
        },
    };
    if let Some(route) = route {
        podssh_ws::names::check_node_name(route)
            .map_err(|_| Refusal::usage(format!("TO {word}: {route:?} is not a route")))?;
    }
    if doc.member(node).is_none() {
        return Err(Refusal::usage(format!("TO {word}: the net {} has no member {node}; TO is {forms}", doc.name)));
    }
    Ok(if exit { Want::Exit(node) } else { Want::Node { node, route } })
}

/// The owner's `set FILE` and `clear`: the next document, and what to say.
pub(super) fn change(
    before: &Doc,
    args: &NetArgs,
    issued: i64,
    expires: i64,
    err: &mut dyn Write,
) -> Result<(Doc, String), Refusal> {
    match args.args[0].as_str() {
        "set" => set(before, args, issued, expires, err),
        _ => clear(before, issued, expires),
    }
}

fn data(why: String) -> Refusal {
    Refusal { message: why, code: sysexits::EX_DATAERR }
}

/// `set FILE`: a policy of JSON, checked strictly, in place of the one held;
/// the document then requires the policy, so that an end that cannot read
/// it keeps the document before rather than skip its rules.
fn set(before: &Doc, args: &NetArgs, issued: i64, expires: i64, err: &mut dyn Write) -> Result<(Doc, String), Refusal> {
    let file = args.args[1].as_str();
    let value = read_json(file)?;
    let (read, said) = policy::checked(&value, before).map_err(|why| data(format!("{file}: {why}")))?;
    for line in said {
        let _ = writeln!(err, "podssh net: {file}: {line}");
    }
    let next = before.next_whole(issued, expires, |whole| {
        whole.insert(policy::FIELD.into(), value);
        require(whole, true);
    });
    let next = next.map_err(data)?;
    // What it changes, before the signature makes it live (T-749).
    for line in policy_diff::diff(before, &next).lines(20) {
        let _ = writeln!(err, "podssh net: {line}");
    }
    if let Some(expect) = &args.expect {
        let mut lines = Vec::new();
        let failed = expectations(&next, &read_json(expect)?, expect, &mut lines)?;
        let _ = err.write_all(&lines);
        if failed > 0 {
            return Err(data(format!("{expect}: {failed} cases are false under {file}: nothing is signed")));
        }
    }
    let (rules, tags) = (read.rules.len(), read.tags.len());
    Ok((next, format!("set the policy: {rules} rules, {tags} tags")))
}

/// `clear`: no policy, so each member reaches each again.
fn clear(before: &Doc, issued: i64, expires: i64) -> Result<(Doc, String), Refusal> {
    if before.policy.is_none() {
        return Err(Refusal::usage(format!("the net {} has no policy to clear", before.name)));
    }
    let next = before.next_whole(issued, expires, |whole| {
        whole.remove(policy::FIELD);
        require(whole, false);
    });
    Ok((next.map_err(data)?, "cleared the policy: each member reaches each".to_string()))
}

/// `requires` with the policy's part, or without it; each other part stays.
fn require(whole: &mut Map<String, Value>, on: bool) {
    let mut parts = whole.get("requires").and_then(Value::as_array).cloned().unwrap_or_default();
    parts.retain(|part| part.as_str() != Some(policy::PART));
    if on {
        parts.push(json!(policy::PART));
    }
    whole.insert("requires".into(), Value::Array(parts));
}
