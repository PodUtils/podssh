//! The audit log's own parts (T-116): the chain against each kind of
//! edit, one table; the tail of a file cut short; and a file that two runs
//! append to, mode 0600, whose write that fails is said once.

use std::io::Cursor;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value};

use super::chain::{self, digest, verify, GENESIS};
use super::{coverage, render, Level};

/// A scratch directory, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("podssh-audit-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

/// Lines of one run as serve writes them, each chained to the one before.
fn chained(events: &[(&str, Map<String, Value>)]) -> Vec<String> {
    let mut prev = GENESIS.to_string();
    let mut lines = Vec::new();
    for (event, more) in events {
        let mut f = more.clone();
        f.insert("run".into(), Value::from("r1"));
        f.insert("prev".into(), Value::from(prev.clone()));
        let line = render(UNIX_EPOCH + Duration::from_secs(1_800_000_000), event, Level::Info, &f);
        prev = digest(line.as_bytes());
        lines.push(line);
    }
    lines
}

fn a_run(commands: bool, with_command: bool) -> Vec<String> {
    let mut start = fields(&[("channel", Value::from(0)), ("request", Value::from("exec"))]);
    if with_command {
        start.insert("command".into(), Value::from("echo hi"));
    }
    chained(&[
        ("serve.start", fields(&[("coverage", coverage(commands))])),
        ("serve.auth.accepted", fields(&[("key", Value::from("SHA256:x"))])),
        ("serve.session.start", start),
        ("serve.session.end", fields(&[("exit_status", Value::from(0))])),
        ("serve.stop", Map::new()),
    ])
}

fn text(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

fn check(text: &str) -> chain::Verdict {
    verify(&mut Cursor::new(text.as_bytes())).unwrap()
}

/// Each kind of change to a log, and what the check says of it.
#[test]
fn the_check_finds_each_kind_of_change() {
    let run = a_run(false, false);
    let edited = {
        let mut l = run.clone();
        l[1] = l[1].replace("SHA256:x", "SHA256:y");
        text(&l)
    };
    let removed = text(&[&run[..2], &run[3..]].concat());
    let added = {
        let mut l = run.clone();
        l.insert(2, l[1].clone());
        text(&l)
    };
    let head_cut = text(&run[1..]);
    let tail_cut = text(&run[..4]);
    let half_line = format!("{}{}", text(&run[..4]), &run[4][..20]);
    let not_json = format!("{}not json\n", text(&run));
    let command_declined = text(&a_run(false, true));
    let command_recorded = text(&a_run(true, true));
    // (case, whether it holds, the first problem's words, an unfinished run)
    let cases: [(&str, String, bool, &str, bool); 10] = [
        ("intact", text(&run), true, "", false),
        ("a line edited", edited, false, "line 3: the chain breaks", false),
        ("a line removed", removed, false, "line 3: the chain breaks", false),
        ("a line put in", added, false, "line 3: the chain breaks", false),
        ("the head cut", head_cut, false, "line 1: the chain breaks", false),
        ("the tail cut at a line", tail_cut, true, "", true),
        ("a write cut short", half_line, false, "line 5: the last line has no end", true),
        ("a line that is no JSON", not_json, false, "line 6: not a line of the audit log", false),
        ("a command its run declined", command_declined, false, "line 3: holds a command line", false),
        ("a command its run recorded", command_recorded, true, "", false),
    ];
    for (case, log, holds, first, unfinished) in cases {
        let verdict = check(&log);
        assert_eq!(verdict.holds(), holds, "{case}: {verdict:?}");
        if !first.is_empty() {
            assert!(verdict.problems[0].starts_with(first), "{case}: {:?}", verdict.problems);
        }
        assert_eq!(!verdict.unfinished.is_empty(), unfinished, "{case}: {verdict:?}");
    }
    assert_eq!(check(&text(&run)).last, digest(run[4].as_bytes()), "the last hash");
    assert_eq!(check("").last, GENESIS);
}

/// A line's keys come in the schema's order, `schema` first.
#[test]
fn a_line_has_the_keys_of_the_log_schema() {
    let line = render(UNIX_EPOCH, "serve.start", Level::Warn, &fields(&[("a", Value::from(1))]));
    assert_eq!(
        line,
        r#"{"schema":1,"time":"1970-01-01T00:00:00Z","level":"warn","event":"serve.start","fields":{"a":1}}"#
    );
}

/// The tail of a file: its last line's hash, and whether a write was cut.
#[test]
fn the_tail_is_the_last_line_whole_or_cut() {
    let dir = Scratch::new("tail");
    let path = dir.0.join("log");
    for (body, line, cut) in [("", None, false), ("a\nbc\n", Some("bc"), false), ("a\nbc", Some("bc"), true)] {
        std::fs::write(&path, body).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let (prev, was_cut) = chain::tail(&file).unwrap();
        assert_eq!(prev, line.map_or(GENESIS.to_string(), |l| digest(l.as_bytes())), "{body:?}");
        assert_eq!(was_cut, cut, "{body:?}");
    }
}

/// Two runs on one file, as two serve processes: one chain, mode 0600; a
/// file that others may read refuses the start. Unix's, as serve is.
#[cfg(unix)]
#[test]
fn two_runs_append_one_chain_to_a_private_file() {
    use super::Audit;
    let dir = Scratch::new("runs");
    let path = dir.0.join("audit.log");
    for _ in 0..2 {
        let audit = Audit::open(&path, false, None).unwrap();
        audit.started("stdio");
        audit.line("serve.conn.open", Level::Info, Map::new());
        audit.stopped("ok");
    }
    let verdict = check(&std::fs::read_to_string(&path).unwrap());
    assert!(verdict.holds() && verdict.lines == 6 && verdict.unfinished.is_empty(), "{verdict:?}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let refused = Audit::open(&path, false, None).expect_err("others may read it");
    assert!(refused.starts_with("--audit-log ") && refused.contains("chmod 600"), "{refused}");
}

/// A write that fails is said once, however many lines fail after it.
#[cfg(unix)]
#[test]
fn a_failed_write_is_said_once() {
    use super::Audit;
    use crate::server::Say;
    use std::sync::{Arc, Mutex};
    let dir = Scratch::new("fail");
    let path = dir.0.join("audit.log");
    let said = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = said.clone();
    let say = Say(Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_string())));
    let audit = Audit::open(&path, false, Some(say)).unwrap();
    // The file becomes a directory: no write can take.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    for _ in 0..3 {
        audit.line("serve.conn.open", Level::Info, Map::new());
    }
    audit.flush();
    let said = said.lock().unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("could not be written") && said[0].contains("the sessions go on"), "{said:?}");
}

/// A log under a directory that is not there names that directory, not a
/// lock file, and carries no "(os error N)".
#[cfg(unix)]
#[test]
fn a_log_in_a_missing_directory_names_the_directory() {
    use super::Audit;
    let dir = Scratch::new("nodir");
    let gone = dir.0.join("none");
    let refused = Audit::open(&gone.join("a.log"), false, None).expect_err("no directory");
    let want = format!("the directory {} does not exist", gone.display());
    assert!(refused.starts_with("--audit-log ") && refused.ends_with(&want), "{refused}");
    assert!(!refused.contains("lock file") && !refused.contains("os error"), "{refused}");
}
