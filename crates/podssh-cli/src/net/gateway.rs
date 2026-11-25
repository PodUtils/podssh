//! A gateway's routes in the net's signed document (T-902): the field
//! `gateways`, an object keyed by the gateway's name, each with `routes`,
//! the blocks of a route file of `podssh serve --gateway FILE` (T-836) as
//! text, each `ca-key` the CA's public half. The owner signs them in one
//! place (`podssh net gateway set NAME FILE`, `super::gateway_cmd`); the
//! gateway (`podssh serve --gateway net:NAME`) reads its own section and
//! finds each CA's private key among the files of its `--gateway-ca`, which
//! never leave its host. The blocks are read by the route file's one reader
//! (`podssh_ssh::server::gateway::routes::plan`), with its refusals.
//!
//! Only the gateway that a section names reads it; each other end keeps
//! the field as one it does not know. So `requires` does not name it, and a
//! podssh of before T-902 takes the document as before. A section that this
//! podssh does not read (a later field, a wrong form, a block that does not
//! read) is refused by the gateway, which then lets nobody in by it: what a
//! gateway cannot read never opens a route.

use std::path::PathBuf;
use std::sync::Arc;

use podssh_ssh::known_hosts::fingerprint;
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};
use podssh_ssh::server::gateway::routes::{self, Routes};
use serde_json::Value;

use super::doc::{check_name, Doc};

/// The document's field.
pub const FIELD: &str = "gateways";
/// The fields of one gateway that this podssh reads.
const GATEWAY_FIELDS: &[&str] = &["routes"];

/// A CA key of `--gateway-ca`: its file, and the key.
pub type Ca = (PathBuf, Arc<PrivateKey>);

/// The routes text of the gateway `name` in `doc`; none when the document
/// has no section for it. `Err` for a section of a form that this podssh
/// does not read.
pub fn section<'a>(doc: &'a Doc, name: &str) -> Result<Option<&'a str>, String> {
    let Some(all) = doc.field(FIELD) else { return Ok(None) };
    let all = all.as_object().ok_or("the document's \"gateways\" is not an object")?;
    let Some(one) = all.get(name) else { return Ok(None) };
    let one = one.as_object().ok_or(format!("the gateway {name} of the document is not an object"))?;
    if let Some(field) = one.keys().find(|k| !GATEWAY_FIELDS.contains(&k.as_str())) {
        return Err(format!(
            "the gateway {name} has the field {field:?}, which this podssh does not read; podssh update"
        ));
    }
    let text = one.get("routes").ok_or(format!("the gateway {name} has no \"routes\""))?;
    text.as_str().map(Some).ok_or(format!("the gateway {name}'s \"routes\" is not text"))
}

/// The names of the gateways that `doc` holds, in order.
pub fn names(doc: &Doc) -> Vec<String> {
    doc.field(FIELD).and_then(Value::as_object).map(|all| all.keys().cloned().collect()).unwrap_or_default()
}

/// The CA's public key of a document's `ca-key` word.
fn ca_public(word: &str) -> Result<PublicKey, String> {
    PublicKey::from_openssh(word).map_err(|_| {
        "in a net's document, ca-key is the CA's public key, TYPE BASE64: its private key stays on the gateway's host, \
         named by --gateway-ca"
            .to_string()
    })
}

/// The owner's check of `text` before it is signed for the gateway `name`:
/// the blocks read as a route file's, each `ca-key` a public key, and one
/// route at least. The count of its routes.
pub fn check(name: &str, text: &str) -> Result<usize, String> {
    check_name(name).map_err(|why| format!("the gateway's name {why}"))?;
    let planned = routes::plan(text)?;
    for route in &planned {
        ca_public(&route.ca).map_err(|why| format!("line {}: ca-key {why}", route.line))?;
    }
    if planned.is_empty() {
        return Err(format!(
            "no route, so nobody could pass the gateway {name}: give route PATTERN and its parts, or remove its \
             routes with podssh net gateway rm {name}"
        ));
    }
    Ok(planned.len())
}

/// The routes of the gateway `name` in `doc`, each with the key of `cas`
/// whose public half its `ca-key` names, and a line for each route left
/// out: one whose CA is no key of `cas`, or whose `ca-key` is no public key.
/// `Err` for a section that is not there or does not read: the caller lets
/// nobody in by it.
pub fn routes_of(doc: &Doc, name: &str, cas: &[Ca]) -> Result<(Routes, Vec<String>), String> {
    let at = format!("the net {} (serial {})", doc.name, doc.serial);
    let text = section(doc, name).map_err(|why| format!("{at}: {why}"))?.ok_or_else(|| {
        format!(
            "{at} holds no routes for the gateway {name}; its owner sets them with podssh net gateway set {name} FILE"
        )
    })?;
    let planned = routes::plan(text).map_err(|why| format!("{at}, the routes of {name}, {why}"))?;
    let held: Vec<String> = cas.iter().map(|(_, key)| fingerprint(key.public_key())).collect();
    let (mut taken, mut notes) = (Vec::new(), Vec::new());
    for route in planned {
        let (pattern, line) = (route.pattern.clone(), route.line);
        let left = |why: String| format!("{at}: route {pattern} (line {line}) refused: {why}");
        let public = match ca_public(&route.ca) {
            Ok(public) => public,
            Err(why) => {
                notes.push(left(format!("ca-key {why}")));
                continue;
            }
        };
        match cas.iter().find(|(_, key)| key.public_key().key_data() == public.key_data()) {
            Some((path, key)) => taken.push(route.with_ca(path.clone(), key.clone())),
            None => notes.push(left(format!(
                "its ca-key {} is the public half of no key of --gateway-ca ({})",
                fingerprint(&public),
                if held.is_empty() { "none given".to_string() } else { held.join(", ") }
            ))),
        }
    }
    Ok((Routes::of(taken), notes))
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
