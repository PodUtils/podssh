//! `--result-file FILE` (T-054): at the end of each run of `podssh ssh`, one
//! JSON object in FILE, so that a script tells the remote command's status
//! from a failure of podssh, and reads the signal, the bytes and the relay,
//! with no parsing of stderr. The command's output never goes into it; its
//! stdout and stderr stay as they are. The parts of the object that other
//! verbs give too (`each`, T-484; `cp`, `mv`, `scp`, `run` and `sftp`,
//! T-486), and the one writer, are here.

use std::io::Write;
use std::time::{Duration, Instant};

use podssh_ssh::outcome::{Facts, Record};
use serde_json::{json, Map, Value};

/// The version of the object's form.
pub const SCHEMA: u32 = 1;

/// The object of a run that started at `started` and exits with `exit`.
pub fn object(exit: i32, started: Instant) -> Value {
    let record = podssh_ssh::outcome::record();
    let f = &record.facts;
    // With no session and no cause said, a refusal of the command line or
    // of the configuration ended the run, or podssh got no session.
    let failure = f.failure.or(match f.end {
        Some(_) => None,
        None => refused(exit),
    });
    let end = f.end.or(failure.map(|_| "failed"));
    // A control master carries the bytes of a run that goes through it.
    let counted = (!f.shared).then(|| bytes(&record));
    let mut object = json!({
        "schema": SCHEMA,
        "exit": exit,
        "status": f.status,
        "signal": signal(f),
        "end": end,
        "failure": failure,
        "bytes": counted,
        "duration_ms": started.elapsed().as_millis() as u64,
        "relay": relay(f),
    });
    // The forwards of the run, only where it had any (T-840): a reader of
    // the object of a run with none sees the keys it always saw.
    let forwards = podssh_ssh::tally::snapshots();
    if let (false, Value::Object(map)) = (forwards.is_empty(), &mut object) {
        map.insert("forwards".into(), forwards.iter().map(forward).collect());
    }
    object
}

/// One forward: its name as written, its state word (T-840; `closed` once
/// `~C` stopped it, T-866) with the server's reason of a refusal, whether
/// `~C` stopped it, and its counts (T-041).
pub(crate) fn forward(f: &podssh_ssh::tally::Forward) -> Value {
    json!({
        "name": f.name,
        "state": f.word(),
        "reason": f.reason,
        "closed": f.closed,
        "connections": f.opened,
        "open": f.open,
        "failed": f.failed,
        "bytes_up": f.up,
        "bytes_down": f.down,
    })
}

/// Each forward of the command line, named in the table before anything
/// connects (T-866): a run that fails before its link lists them too, each
/// `bound`, as its listener is or its request is asked for.
pub(crate) fn name_forwards(opts: &podssh_ssh::Options) {
    for forward in &opts.local_forwards {
        podssh_ssh::tally::of(&forward.shown);
    }
    for forward in &opts.remote_forwards {
        podssh_ssh::tally::of(&podssh_ssh::remote::name(forward));
    }
    if let podssh_ssh::Request::StdioForward(target) = &opts.request {
        podssh_ssh::tally::of(&podssh_ssh::forward::stdio_name(target));
    }
}

/// The class of a run that ended with `exit` and no session: a refusal of
/// the command line (`usage`) or of the configuration (`config`), a road
/// that this build lacks (`not-built`), else no connection.
pub(crate) fn refused(exit: i32) -> Option<&'static str> {
    match exit {
        0 => None,
        64 => Some("usage"),
        78 => Some("config"),
        70 => Some("not-built"),
        _ => Some("connect"),
    }
}

/// The signal of the record, its name and whether it dumped core; null
/// with none.
pub(crate) fn signal(f: &Facts) -> Value {
    f.signal.as_ref().map_or(Value::Null, |(name, core)| json!({ "name": name, "core_dumped": core }))
}

/// The bytes of the session's stdin, stdout and stderr.
pub(crate) fn bytes(record: &Record) -> Value {
    json!({ "stdin": record.stdin, "stdout": record.stdout, "stderr": record.stderr })
}

/// The relay host that opened the session, with its close; null with no
/// relay.
pub(crate) fn relay(f: &Facts) -> Value {
    f.relay_host.as_ref().map_or(Value::Null, |host| {
        let (code, reason) = f.relay_close.clone().unwrap_or_default();
        json!({ "host": host, "close_code": code, "reason": (!reason.is_empty()).then_some(reason) })
    })
}

/// The keys that each verb's object gives beside `ssh`'s (T-486), in the
/// meaning of `ssh`'s, with `verb` and `error`: `failure` is the class, and
/// `error` its words; `relay` adds `sessions`, the relay sessions that the
/// run opened. `ssh`'s own object keeps its keys, which its readers hold.
pub(crate) fn common(
    verb: &str,
    exit: i32,
    took: Duration,
    f: &Facts,
    failure: Option<&str>,
    error: Option<&str>,
) -> Map<String, Value> {
    let mut relay = relay(f);
    if let Some(relay) = relay.as_object_mut() {
        relay.insert("sessions".into(), f.relay_sessions.into());
    }
    let mut object = Map::new();
    object.insert("schema".into(), SCHEMA.into());
    object.insert("verb".into(), verb.into());
    object.insert("exit".into(), exit.into());
    object.insert("failure".into(), failure.into());
    object.insert("error".into(), error.into());
    object.insert("duration_ms".into(), (took.as_millis() as u64).into());
    object.insert("relay".into(), relay);
    object
}

/// `--result-file -` of a verb whose stdout is its own output: refused,
/// as for `ssh`; whether it was, said on `err`.
pub(crate) fn dash(verb: &str, path: Option<&str>, err: &mut dyn Write) -> bool {
    if path != Some("-") {
        return false;
    }
    let _ = writeln!(err, "podssh {verb}: --result-file -: stdout carries the run's own output; name a file");
    true
}

/// The verdict of the end-to-end channel to a node (T-088), which says more
/// than the session saw: a refused key is `auth`, a node out of reach
/// `relay`, and another fault `session`.
pub fn channel_failed(fault: &crate::exitmap::Fault) {
    use crate::exitmap::Fault;
    podssh_ssh::outcome::failure_is(match fault {
        Fault::Auth => "auth",
        Fault::RelayUnreachable => "relay",
        _ => "session",
    });
}

/// Why `path` could not take the record at the end of a run: its
/// directory is missing, or is no directory. A copy says so before it
/// connects (T-928); `None` when it can be tried.
pub(crate) fn no_place(path: &str) -> Option<String> {
    let dir = std::path::Path::new(path).parent().filter(|d| !d.as_os_str().is_empty());
    let dir = dir.unwrap_or(std::path::Path::new("."));
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => None,
        Ok(_) => Some(format!("--result-file {path}: {} is not a directory", dir.display())),
        Err(_) => Some(format!("--result-file {path}: no such directory: {}", dir.display())),
    }
}

/// Write `object` to `path` as a new file for its owner alone: a private
/// file beside it, then renamed onto it, so that a file that was there,
/// with its mode, is replaced and never written through (T-928). A failure
/// is a line on stderr of `verb`; whether the record was written, for a
/// verb whose exit says so.
pub fn write(verb: &str, path: &str, object: &Value, err: &mut dyn Write) -> bool {
    let target = std::path::Path::new(path);
    let body = format!("{object}\n");
    // A FIFO or a device (`/dev/stderr`) takes the record as it is: no file
    // is renamed onto it, by the one check of the copies' too (T-1038).
    let special = crate::cp::special::local(target).is_some();
    let placed = match special {
        true => std::fs::OpenOptions::new().write(true).open(target).and_then(|mut f| f.write_all(body.as_bytes())),
        false => replace(target, body.as_bytes()),
    };
    if let Err(e) = placed {
        let _ = writeln!(err, "podssh {verb}: --result-file {path}: {}", crate::cp::words::said(&e));
        return false;
    }
    true
}

/// `body` at `target` as a new file of mode 0600: written beside it under a
/// private name, then renamed onto it.
fn replace(target: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let leaf = target.file_name().and_then(|n| n.to_str()).unwrap_or("result");
    let temp = target.with_file_name(format!(".{leaf}.podssh-{:016x}.part", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(body)?;
        file.sync_all()
    });
    let placed = written.and_then(|()| std::fs::rename(&temp, target));
    if placed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    placed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record is a new file for its owner alone, also over a file that
    /// was there with another mode, and a missing directory is found before
    /// the run (T-928).
    #[test]
    fn the_record_is_a_new_private_file_and_its_directory_is_looked_at_first() {
        let dir = std::env::temp_dir().join(format!("podssh-result-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.json");
        std::fs::write(&path, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let shown = path.display().to_string();
        let mut err = Vec::new();
        assert!(write("cp", &shown, &json!({"exit": 0}), &mut err), "{}", String::from_utf8_lossy(&err));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"exit\":0}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:o}");
        }
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 1, "no temporary name stays: {left:?}");
        assert_eq!(no_place(&shown), None);
        assert_eq!(no_place("r.json"), None, "the current directory");
        let missing = dir.join("no/r.json").display().to_string();
        assert!(no_place(&missing).is_some_and(|why| why.contains("no such directory")), "{missing}");
        let under_file = path.join("r.json").display().to_string();
        assert!(no_place(&under_file).is_some_and(|why| why.contains("is not a directory")));
        let mut err = Vec::new();
        assert!(!write("cp", &missing, &json!({}), &mut err), "a missing directory fails");
        let said = String::from_utf8_lossy(&err);
        assert!(said.starts_with("podssh cp: --result-file ") && !said.contains("os error"), "{said}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
