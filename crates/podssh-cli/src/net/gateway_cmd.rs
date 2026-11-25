//! `podssh net gateway` (T-902): the owner's `set NAME FILE` and `rm NAME`,
//! which sign a new document as each change of the net does
//! (`super::edit`), and each end's `show NAME`, which gives the routes back
//! as a file that `set` takes again. FILE is a route file of `podssh serve
//! --gateway FILE` (T-836) whose each `ca-key` is the CA's public key, as
//! the private key stays on the gateway's host (`super::gateway`).

use std::io::Write;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::doc::{Doc, MAX_DOC};
use super::gateway::{self, FIELD};
use super::{held, summary, NetArgs};
use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// The words of `gateway`, as a refusal names them.
const WORDS: &str = "set NAME FILE, show NAME or rm NAME";

/// The count of words after `net`, its verb included, and their shape.
pub(super) fn shape(args: &[String]) -> Result<(usize, &'static str), Refusal> {
    match args.first().map(String::as_str) {
        Some("set") => Ok((3, "gateway set NAME FILE")),
        Some("show") => Ok((2, "gateway show NAME")),
        Some("rm") => Ok((2, "gateway rm NAME")),
        Some(other) => Err(Refusal::usage(format!("podssh net gateway {other:?}: {WORDS}"))),
        None => Err(Refusal::usage(format!("podssh net gateway: {WORDS}"))),
    }
}

/// Whether the verb is the owner's, which signs a new document.
pub(super) fn signs(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("set" | "rm"))
}

/// Each end's verb: `show NAME`, the routes on stdout as `set` takes them.
pub(super) fn run(args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let held = held()?;
    let _ = writeln!(err, "podssh net: {}", summary(&held));
    let (doc, name) = (&held.signed.doc, args.args[1].as_str());
    match gateway::section(doc, name).map_err(data)? {
        Some(text) => {
            let _ = out.write_all(text.as_bytes());
            if !text.ends_with('\n') {
                let _ = writeln!(out);
            }
            Ok(0)
        }
        None => Err(none_for(doc, name)),
    }
}

/// The owner's `set NAME FILE` and `rm NAME`: the next document, and what
/// to say.
pub(super) fn change(
    before: &Doc,
    args: &NetArgs,
    issued: i64,
    expires: i64,
    err: &mut dyn Write,
) -> Result<(Doc, String), Refusal> {
    let name = args.args[1].as_str();
    match args.args[0].as_str() {
        "set" => set(before, name, &args.args[2], issued, expires, err),
        _ => rm(before, name, issued, expires),
    }
}

/// `set NAME FILE`: the routes of FILE, checked as the gateway reads them,
/// in place of the gateway's routes held.
fn set(
    before: &Doc,
    name: &str,
    file: &str,
    issued: i64,
    expires: i64,
    err: &mut dyn Write,
) -> Result<(Doc, String), Refusal> {
    let text = read_text(file)?;
    let count = gateway::check(name, &text).map_err(|why| data(format!("{file}: {why}")))?;
    // A section that this podssh does not read is a later podssh's: never
    // dropped by a change made here.
    let replaced = gateway::section(before, name).map_err(data)?.is_some();
    let next = before.next_whole(issued, expires, |whole| {
        let mut all = gateways(whole);
        all.insert(name.to_string(), json!({ "routes": text }));
        whole.insert(FIELD.into(), Value::Object(all));
    });
    let next = next.map_err(data)?;
    if before.member(name).is_none() {
        let _ = writeln!(
            err,
            "podssh net: the gateway {name} is no member's name: podssh serve --gateway net:{name} reads it all the same"
        );
    }
    let how = if replaced { "in place of the routes before" } else { "the first" };
    Ok((next, format!("set the routes of the gateway {name}: {count} routes, {how}")))
}

/// `rm NAME`: the gateway's routes out of the document, so that it lets
/// nobody in by them once it reads the next serial.
fn rm(before: &Doc, name: &str, issued: i64, expires: i64) -> Result<(Doc, String), Refusal> {
    if gateway::section(before, name).map_err(data)?.is_none() {
        return Err(none_for(before, name));
    }
    let next = before.next_whole(issued, expires, |whole| {
        let mut all = gateways(whole);
        all.remove(name);
        match all.is_empty() {
            true => whole.remove(FIELD),
            false => whole.insert(FIELD.into(), Value::Object(all)),
        };
    });
    let said =
        format!("removed the routes of the gateway {name}: it lets nobody in by the net once it reads this serial");
    Ok((next.map_err(data)?, said))
}

/// The gateways of the document's object; `section` refused a field that is
/// not an object before any change is made.
fn gateways(whole: &Map<String, Value>) -> Map<String, Value> {
    whole.get(FIELD).and_then(Value::as_object).cloned().unwrap_or_default()
}

/// The refusal of a gateway that the document has no routes for.
fn none_for(doc: &Doc, name: &str) -> Refusal {
    let names = gateway::names(doc);
    let held = if names.is_empty() { "none".to_string() } else { names.join(", ") };
    Refusal::usage(format!(
        "the net {} (serial {}) holds no routes for the gateway {name}; its gateways: {held}",
        doc.name, doc.serial
    ))
}

/// The text of `file`: there (66), at most what a document holds, and
/// UTF-8 (65).
fn read_text(file: &str) -> Result<String, Refusal> {
    let path = Path::new(file);
    let no_input = |why: String| Refusal { message: why, code: sysexits::EX_NOINPUT };
    if !path.exists() {
        return Err(no_input(format!("{file}: no such file")));
    }
    let bytes = std::fs::read(path).map_err(|e| no_input(format!("{file}: {e}")))?;
    if bytes.len() > MAX_DOC {
        return Err(data(format!("{file} has {} bytes, more than a net's document holds", bytes.len())));
    }
    String::from_utf8(bytes).map_err(|_| data(format!("{file} is not UTF-8 text")))
}

fn data(why: String) -> Refusal {
    Refusal { message: why, code: sysexits::EX_DATAERR }
}
