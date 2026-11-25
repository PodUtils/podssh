//! T-952: an `std::io::Error` reaches a user line through `podssh_ws::text::said`, which takes Rust's
//! "(os error N)" off the system's words, and never by `{e}` or `e.to_string()`. This scans the sources of
//! the commands that serve and relay (`node`, `operator`, `relay`, `proxy`, `chat`, `funnel`, `serve`, `net`,
//! `pipe`, `health`, `ping`, the forwarders, the carriers and the roads) outside their test code. A hit is
//! allowed only where the value is no I/O error: it is listed in `NOT_IO` with its whole line, and a listed
//! line that is gone fails the test, so the list cannot rot. A name other than `e`, `err` or `error` is not
//! seen: the scan pins the usual shape of the fault, and the review of a new site pins the rest. The
//! sources of the other commands (`ssh`, the local tools, `run`, `each`, `job`, `session`) join the scan as
//! each is done.

use std::path::{Path, PathBuf};

/// Lines that show a value which is no I/O error (a parser's, a JSON reader's, a key's, a session record's),
/// as (file under `src/`, the line without its indent).
#[rustfmt::skip]
const NOT_IO: &[(&str, &str)] = &[
    ("carrier_dns_file.rs", r#"Duration::try_from_secs_f64(secs).map_err(|e| format!("{name} {}: {e}", visible(value, SHOWN)))"#),
    ("carrier_dns_file.rs", r#"settings.check().map_err(|e| e.to_string())?;"#),
    ("chat/irc/files.rs", r#"deny(&from, &offer.transfer_id, "declined").map_err(|e| e.to_string())"#),
    ("chat/irc/files.rs", r#"let sender = Sender::new(transfer_id.clone(), name, size, limits).map_err(|e| e.to_string())?;"#),
    ("chat/talk.rs", r#".map_err(|e| e.to_string()),"#),
    ("chat/talk.rs", r#"Act::Say(text) => self.session.text(&text).map(|(_, record)| self.send(record)).map_err(|e| e.to_string()),"#),
    ("chat/talk.rs", r#"Err(e) => return Some(Ended::Failed(e.to_string())),"#),
    ("chat/talk.rs", r#"let (id, record) = self.session.text(&text).map_err(|e| e.to_string())?;"#),
    ("chat/talk.rs", r#"let record = self.session.chunk(id, data).map_err(|e| e.to_string())?;"#),
    ("chat/talk.rs", r#"return Err(e.to_string());"#),
    ("forwarder/nodes_live.rs", r#".map_err(|e| e.to_string())?;"#),
    ("net/doc.rs", r#"let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("the document is not JSON: {e}"))?;"#),
    ("net/doc.rs", r#"podssh_ssh::russh::keys::PublicKey::from_openssh(&owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/policy_cmd.rs", r#"serde_json::from_slice(&bytes).map_err(|e| data(format!("{file} is not JSON: {e}")))"#),
    ("net/sign.rs", r#"let line = PublicKey::new(public.key_data().clone(), "").to_openssh().map_err(|e| e.to_string())?;"#),
    ("net/sign.rs", r#"let owner = PublicKey::from_openssh(&doc.owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/sign.rs", r#"let owner = PublicKey::from_openssh(owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/sign.rs", r#"let prehash = sshsig::digest(&mut &bytes[..], HashAlg::Sha512).map_err(|e| e.to_string())?;"#),
    ("net/sign.rs", r#"let prehash = sshsig::digest(&mut &bytes[..], read.signature.hash_alg()).map_err(|e| e.to_string())?;"#),
    ("node_install/env.rs", r#"let vars = parse(&text).map_err(|e| Refusal::config(format!("--env-file {}: {e}", path.display())))?;"#),
    ("node_upgrade/pass.rs", r#"let Decoded { from, sessions, parts } = state::decode(bytes).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass.rs", r#"let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass_windows.rs", r#"let Decoded { from, sessions, parts } = state::decode(&bytes).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass_windows.rs", r#"let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;"#),
    ("relay_conform_forward.rs", r#"let key = podssh_ws::handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;"#),
    ("relay_diag_text.rs", r#"let from = text(&doc["you"]["edge_colo"]).map(|e| format!("edge {e}"));"#),
    ("relay_diag_text.rs", r#"return vec![format!("{head}: the relay did not dial it: {error}")];"#),
];

/// Whether the first path component, without `.rs`, names a command of the scan.
fn in_scope(rel: &str) -> bool {
    const EXACT: &[&str] = &[
        "operator",
        "chat",
        "net",
        "pipe",
        "health",
        "forwarder",
        "layered",
        "h2_road",
        "dns_road",
        "gsr",
        "hyperdht",
        "iroh_way",
        "funnel",
        "proxy",
        "relay",
        "serve",
        "node",
    ];
    const PREFIX: &[&str] = &[
        "node_",
        "operator_",
        "relay_",
        "proxy_",
        "funnel_",
        "serve_",
        "serveo_",
        "ping",
        "pinggy_",
        "carrier",
        "http_road",
    ];
    let first = rel.split('/').next().unwrap_or(rel);
    let stem = first.strip_suffix(".rs").unwrap_or(first);
    EXACT.contains(&stem) || PREFIX.iter().any(|p| stem.starts_with(p))
}

/// Whether `line` shows an error named `e`, `err` or `error` by its `Display`: inline (`{e}`) or by
/// `e.to_string()`.
fn shows_display(line: &str) -> bool {
    let named = ["e", "err", "error"];
    if named.iter().any(|n| line.contains(&format!("{{{n}}}"))) {
        return true;
    }
    named.iter().any(|n| {
        let call = format!("{n}.to_string()");
        line.match_indices(&call).any(|(at, _)| {
            let before = line[..at].chars().next_back();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
        })
    })
}

/// For each line, whether it is inside a `#[cfg(test)] mod NAME {` block, which ends at the next `}` in
/// column 0.
fn test_blocks(lines: &[&str]) -> Vec<bool> {
    let mut inside = vec![false; lines.len()];
    let mut i = 0;
    while i + 1 < lines.len() {
        let next = lines[i + 1].trim_start();
        let is_mod = ["mod ", "pub mod ", "pub(crate) mod "].iter().any(|p| next.starts_with(p));
        if lines[i].trim() == "#[cfg(test)]" && is_mod && next.trim_end().ends_with('{') {
            let mut j = i + 1;
            while j < lines.len() && lines[j] != "}" {
                j += 1;
            }
            inside[i..(j + 1).min(lines.len())].fill(true);
            i = j;
        }
        i += 1;
    }
    inside
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                sources(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !(name.ends_with("_tests.rs") || name.ends_with("_test.rs") || name == "tests.rs") {
                out.push(path);
            }
        }
    }
}

/// Each hit of the scan, as (file under `src/`, line number, the line without its indent).
fn hits() -> Vec<(String, usize, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    let mut found = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        if !in_scope(&rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let in_test = test_blocks(&lines);
        for (i, line) in lines.iter().enumerate() {
            let shown = line.trim();
            if !in_test[i] && !shown.starts_with("//") && shows_display(shown) {
                found.push((rel.clone(), i + 1, shown.to_string()));
            }
        }
    }
    found
}

#[test]
fn no_io_error_reaches_a_line_by_its_display() {
    let found = hits();
    assert!(found.len() >= NOT_IO.len(), "the scan found {} lines: it reads nothing", found.len());
    let unlisted: Vec<String> = found
        .iter()
        .filter(|(file, _, line)| !NOT_IO.iter().any(|(f, l)| f == file && l == line))
        .map(|(file, at, line)| format!("{file}:{at}: {line}"))
        .collect();
    assert!(
        unlisted.is_empty(),
        "a user line shows an error by its Display, which keeps Rust's \"(os error N)\": use \
         podssh_ws::text::said(&e), or list the line in NOT_IO if the value is no I/O error:\n{}",
        unlisted.join("\n")
    );
    let gone: Vec<String> = NOT_IO
        .iter()
        .filter(|(f, l)| !found.iter().any(|(file, _, line)| file == f && line == l))
        .map(|(f, l)| format!("{f}: {l}"))
        .collect();
    assert!(gone.is_empty(), "NOT_IO lists lines that the scan no longer finds; remove them:\n{}", gone.join("\n"));
}

/// The check on planted shapes: it must fail on the defect and pass on the cure.
#[test]
fn the_scan_sees_the_shapes_of_the_fault_and_only_them() {
    for line in [
        r#"say(format!("a: {e}"))"#,
        r#"let _ = writeln!(err, "b: {err}");"#,
        r#".map_err(|e| e.to_string())?;"#,
        r#"Err(error) => Err(error.to_string()),"#,
    ] {
        assert!(shows_display(line), "{line}");
    }
    for line in [
        r#"say(format!("a: {}", podssh_ws::text::said(&e)))"#,
        r#"format!("{event} {errors} {name}")"#,
        r#"let t = some_e.to_string();"#,
        r#"let t = self.e.to_string();"#,
        r#"let t = then.to_string();"#,
    ] {
        assert!(!shows_display(line), "{line}");
    }
    let lines = ["fn a() {}", "#[cfg(test)]", "mod tests {", "    let _ = \"{e}\";", "}", "fn b() {}"];
    assert_eq!(test_blocks(&lines), [false, true, true, true, true, false]);
    let declared = ["#[cfg(test)]", "mod tests;", "fn b() {}"];
    assert_eq!(test_blocks(&declared), [false, false, false], "a module in a file of its own is no block");
}

#[test]
fn the_scope_names_the_commands_of_the_scan() {
    for rel in ["node.rs", "node_serve.rs", "relay_serve/certs.rs", "pipe/listen.rs", "net/sign.rs", "ping/mod.rs"] {
        assert!(in_scope(rel), "{rel}");
    }
    for rel in ["ssh/config.rs", "cp/words.rs", "doctor/mod.rs", "run_cmd/mod.rs", "keygen.rs", "nofile.rs"] {
        assert!(!in_scope(rel), "{rel}");
    }
}
