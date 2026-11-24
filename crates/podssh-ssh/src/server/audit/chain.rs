//! The chain of the audit log (T-116, after FeroSSH's sealed logs and
//! ssh-mitm's coverage map in the donor study of PodUtils/podssh#317):
//! each line's `fields.prev` is the SHA-256 of the line before it, the
//! first line's is [`GENESIS`]; and the check of a file, which recomputes
//! the chain, and refuses a line that records what its run declined.
//!
//! The chain finds a line that was changed, removed or put in, and a cut at
//! the head. It does not find a cut of the tail: a run with no
//! `serve.stop` reads as unfinished (it may still run). Only a copy of the
//! last hash kept off the host finds that cut; the check prints it.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The `prev` of a file's first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The most of a file's end read for its last line. A line of serve is
/// far shorter (each value of a peer is bounded); a last line past it is
/// not serve's, and the check finds its hash wrong.
pub const TAIL: u64 = 64 * 1024;

/// The longest line that the check reads; past it the check stops.
pub const MOST_LINE: usize = 1 << 20;

/// The most problems that the check names; it counts the rest.
pub const MOST_PROBLEMS: usize = 20;

/// SHA-256 of `line` (no newline), in hex.
pub fn digest(line: &[u8]) -> String {
    Sha256::digest(line).iter().map(|b| format!("{b:02x}")).collect()
}

/// The `prev` of a line appended to `file` now, and whether the file ends
/// inside a line (a write that a crash cut short), which then needs a
/// newline first. The caller holds the file's lock.
pub fn tail(file: &File) -> std::io::Result<(String, bool)> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok((GENESIS.to_string(), false));
    }
    let start = len.saturating_sub(TAIL);
    let mut at = file;
    at.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    at.take(TAIL).read_to_end(&mut buf)?;
    let cut = buf.last() != Some(&b'\n');
    let body = if cut { &buf[..] } else { &buf[..buf.len() - 1] };
    let line = match body.iter().rposition(|&b| b == b'\n') {
        Some(i) => &body[i + 1..],
        None => body,
    };
    Ok((digest(line), cut))
}

/// What the check found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The lines read.
    pub lines: usize,
    /// Each problem, `line N: why`, at most [`MOST_PROBLEMS`].
    pub problems: Vec<String>,
    /// The problems past [`MOST_PROBLEMS`].
    pub more: usize,
    /// The runs with a `serve.start` and no `serve.stop`: still running,
    /// killed, or the tail cut.
    pub unfinished: Vec<String>,
    /// SHA-256 of the last line: the `prev` that the next line will hold.
    pub last: String,
}

impl Verdict {
    /// Whether the chain holds and no line records what its run declined.
    pub fn holds(&self) -> bool {
        self.problems.is_empty() && self.more == 0
    }

    fn problem(&mut self, line: usize, why: &str) {
        if self.problems.len() < MOST_PROBLEMS {
            self.problems.push(format!("line {line}: {why}"));
        } else {
            self.more += 1;
        }
    }
}

/// Check the log that `reader` gives, from its first line.
pub fn verify<R: BufRead>(reader: &mut R) -> std::io::Result<Verdict> {
    let mut verdict = Verdict { last: GENESIS.to_string(), ..Verdict::default() };
    // Each run's coverage map, by its id, in order of the lines.
    let mut runs: HashMap<String, Value> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = reader.by_ref().take(MOST_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
        }
        verdict.lines += 1;
        let n = verdict.lines;
        let ended = buf.last() == Some(&b'\n');
        if !ended && buf.len() > MOST_LINE {
            verdict.problem(n, "longer than 1 MiB, which no line of serve is; the check stops here");
            break;
        }
        let line = if ended { &buf[..buf.len() - 1] } else { &buf[..] };
        if !ended {
            verdict.problem(n, "the last line has no end: a write cut short");
        }
        let expected = std::mem::replace(&mut verdict.last, digest(line));
        let Some(fields) = parse(line) else {
            verdict.problem(n, "not a line of the audit log (one JSON object of schema 1)");
            continue;
        };
        if fields.get("prev").and_then(Value::as_str) != Some(expected.as_str()) {
            verdict.problem(n, "the chain breaks here: a line before it, or this one, was changed, put in or removed");
        }
        let run = fields.get("run").and_then(Value::as_str).unwrap_or_default().to_string();
        match fields.get("event").and_then(Value::as_str) {
            Some("serve.start") => {
                runs.insert(run.clone(), fields.get("coverage").cloned().unwrap_or(Value::Null));
                order.push(run);
            }
            Some("serve.stop") => {
                if runs.remove(&run).is_none() {
                    verdict.problem(n, "a serve.stop of a run that has no serve.start before it");
                }
            }
            Some(_) if !runs.contains_key(&run) => {
                verdict.problem(n, "a line of a run that has no serve.start before it");
            }
            Some("serve.session.start") if fields.contains_key("command") || fields.contains_key("original") => {
                let class = runs.get(&run).and_then(|c| c.get("exec")).and_then(Value::as_str);
                if class != Some("recorded") {
                    verdict.problem(n, "holds a command line, which its run's coverage map declined to record");
                }
            }
            _ => {}
        }
    }
    verdict.unfinished = order.into_iter().filter(|run| runs.contains_key(run)).collect();
    Ok(verdict)
}

/// The fields of a line, with its event in them as `event`; None for a
/// line that is not one object of schema 1 with the schema's keys.
fn parse(line: &[u8]) -> Option<serde_json::Map<String, Value>> {
    let Value::Object(mut top) = serde_json::from_slice::<Value>(line).ok()? else { return None };
    if top.get("schema").and_then(Value::as_u64) != Some(u64::from(pod_core::LOG_SCHEMA)) {
        return None;
    }
    top.get("time").and_then(Value::as_str)?;
    top.get("level").and_then(Value::as_str)?;
    let event = top.remove("event").filter(Value::is_string)?;
    let Some(Value::Object(mut fields)) = top.remove("fields") else { return None };
    fields.insert("event".into(), event);
    Some(fields)
}
