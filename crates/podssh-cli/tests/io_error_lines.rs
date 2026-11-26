//! T-952: an `std::io::Error` reaches a user line through `podssh_ws::text::said`, which takes Rust's
//! "(os error N)" off the system's words, and never by `{e}` or `e.to_string()`. This scans each source
//! file of the crate outside its test code. A hit is allowed only where the value is no I/O error: it is
//! listed in `NOT_IO` with its whole line, and a listed line that is gone fails the test, so the list
//! cannot rot. A line of `cp/` that builds a `Failed` by `Failed::new` (or `failed(Fault::`, its alias)
//! is exempt: that constructor takes the suffix off itself. A name other than `e`, `err` or `error` is
//! not seen: the scan pins the usual shape of the fault, and the review of a new site pins the rest.
//!
//! T-989: the same scan reads `crates/podssh-ssh/src/`, with a table of its own and a list of exempt
//! modules (`SSH_EXEMPT`): modules of codecs whose values are keys, signatures or parser faults and never
//! an I/O error, each with why. An exempt module must still have a hit (else it is stale) and must not
//! touch a file, a socket, a stream or an agent (else it is no codec): its first such line fails the test.

use std::path::{Path, PathBuf};

/// Lines that show a value which is no I/O error (a parser's, a JSON reader's, a key's, a session record's),
/// as (file under `src/`, the line without its indent).
#[rustfmt::skip]
const NOT_IO: &[(&str, &str)] = &[
    ("carrier_dns_file.rs", r#"Duration::try_from_secs_f64(secs).map_err(|e| format!("{name} {}: {e}", visible(value, SHOWN)))"#),
    ("carrier_dns_file.rs", r#"settings.check().map_err(|e| e.to_string())?;"#),
    ("channel.rs", r#"e2e::Error::Timeout(_) => (Fault::RelayUnreachable, e.to_string()),"#),
    ("channel.rs", r#"e2e::Error::NotChannel(_) => (Fault::SessionFault, format!("{e}; --no-e2e turns it off at this end")),"#),
    ("chat/irc/files.rs", r#"let sender = Sender::new(transfer_id.clone(), name, size, limits).map_err(|e| e.to_string())?;"#),
    ("chat/irc/files.rs", r#"deny(&from, &offer.transfer_id, reason).map_err(|e| e.to_string())"#),
    ("chat/talk.rs", r#"let (id, record) = self.session.text(&text).map_err(|e| e.to_string())?;"#),
    ("chat/talk.rs", r#"let record = self.session.chunk(id, data).map_err(|e| e.to_string())?;"#),
    ("chat/talk.rs", r#"Act::Say(text) => self.session.text(&text).map(|(_, record)| self.send(record)).map_err(|e| e.to_string()),"#),
    ("chat/talk.rs", r#".map_err(|e| e.to_string()),"#),
    ("chat/talk.rs", r#"return Err(e.to_string());"#),
    ("chat/talk.rs", r#"Err(e) => return Some(Ended::Failed(e.to_string())),"#),
    ("cp/byexec.rs", r#"base64::engine::general_purpose::STANDARD.decode(&self.pending[..whole]).map_err(|e| e.to_string())?;"#),
    ("exit/listen.rs", r#"Ok(Err(e)) => return refuse(client, e.status().unwrap_or(400), &e.to_string(), prefix).await,"#),
    ("forwarder/nodes_live.rs", r#".map_err(|e| e.to_string())?;"#),
    ("help.rs", r#"pod_manual::help::render(&manual, path).unwrap_or_else(|e| format!("{e}\n"))"#),
    ("keygen.rs", r#"let line = key.public_key().to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;"#),
    ("keygen.rs", r#"let _ = writeln!(err, "podssh keygen: could not encode the public key: {e}");"#),
    ("keygen_cert.rs", r#"let line = certificate.to_openssh().map_err(|e| format!("could not encode the certificate: {e}"))?;"#),
    ("keygen_cert.rs", r#"let _ = writeln!(err, "{path}:{number}: invalid key: {e}");"#),
    ("keygen_change.rs", r#"key.public_key().to_openssh().map_err(|e| failed(format!("could not encode the public key: {e}")))?;"#),
    ("keygen_change.rs", r#"Err(e) => return Err(format!("the new file is no key: {e}")),"#),
    ("keygen_convert.rs", r#"match convert::import(&text, format).and_then(|key| key.to_openssh().map_err(|e| e.to_string())) {"#),
    ("keygen_convert.rs", r#".map_err(|e| format!("could not encode the key: {e}"))"#),
    ("keygen_sk.rs", r#"let line = key.public_key().to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;"#),
    ("keygen_tpm.rs", r#"pcrs: Pcrs::parse(tpm::DEFAULT_PCRS).map_err(|e| e.to_string())?,"#),
    ("keygen_tpm.rs", r#"options.pcrs = Pcrs::parse(list).map_err(|e| format!("-O {option}: {e}"))?;"#),
    ("keygen_tpm.rs", r#"let key = public.to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;"#),
    ("keygen_tpm.rs", r#"let pem = file.to_pem().map_err(|e| e.to_string())?;"#),
    ("keygen_tpm.rs", r#"PolicyKey::new(key).map_err(|e| format!("{}: {e}", path.display()))"#),
    ("keygen_tpm.rs", r#"let pem = new.to_pem().map_err(|e| format!("{} is unchanged: {e}", path.display()))?;"#),
    ("net/doc.rs", r#"let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("the document is not JSON: {e}"))?;"#),
    ("net/doc.rs", r#"podssh_ssh::russh::keys::PublicKey::from_openssh(&owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/policy_cmd.rs", r#"serde_json::from_slice(&bytes).map_err(|e| data(format!("{file} is not JSON: {e}")))"#),
    ("net/sign.rs", r#"let owner = PublicKey::from_openssh(&doc.owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/sign.rs", r#"let prehash = sshsig::digest(&mut &bytes[..], read.signature.hash_alg()).map_err(|e| e.to_string())?;"#),
    ("net/sign.rs", r#"let owner = PublicKey::from_openssh(owner).map_err(|e| format!("the owner's key: {e}"))?;"#),
    ("net/sign.rs", r#"let line = PublicKey::new(public.key_data().clone(), "").to_openssh().map_err(|e| e.to_string())?;"#),
    ("net/sign.rs", r#"let prehash = sshsig::digest(&mut &bytes[..], HashAlg::Sha512).map_err(|e| e.to_string())?;"#),
    ("node_install/env.rs", r#"let vars = parse(&text).map_err(|e| Refusal::config(format!("--env-file {}: {e}", path.display())))?;"#),
    ("node_upgrade/pass.rs", r#"let Decoded { from, sessions, parts } = state::decode(bytes).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass.rs", r#"let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass_windows.rs", r#"let Decoded { from, sessions, parts } = state::decode(&bytes).map_err(|e| e.to_string())?;"#),
    ("node_upgrade/pass_windows.rs", r#"let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;"#),
    ("pairs.rs", r#"pair::file_name(label).map(|_| ()).map_err(|e| Refusal::usage(label_words(&e.to_string())))"#),
    ("pairs.rs", r#"PairError::BadLabel(_) => label_words(&e.to_string()),"#),
    ("pins.rs", r#"Some(text) => podssh_ws::resolve::parse_pins(text).map_err(|e| Refusal::usage(format!("--relay-addr: {e}")))?,"#),
    ("pins.rs", r#"pins.extend(podssh_ws::resolve::parse_pins(&text).map_err(|e| Refusal::config(format!("{PINS_ENV}: {e}")))?);"#),
    ("pins.rs", r#"pins.extend(more.map_err(|e| Refusal::config(format!("{}: RelayAddr {}: {e}", value.at, value.text)))?);"#),
    ("policy.rs", r#"parse(&bytes).map_err(|e| refused(e.to_string()))"#),
    ("relay_conform_forward.rs", r#"let key = podssh_ws::handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;"#),
    ("relay_diag_text.rs", r#"let from = text(&doc["you"]["edge_colo"]).map(|e| format!("edge {e}"));"#),
    ("relay_diag_text.rs", r#"return vec![format!("{head}: the relay did not dial it: {error}")];"#),
    ("session/wire.rs", r#"let value: Value = serde_json::from_slice(text).map_err(|e| usage(format!("not a line of JSON: {e}")))?;"#),
    ("session/wire.rs", r#"let value: Value = serde_json::from_slice(text).map_err(|e| broken(e.to_string()))?;"#),
    ("settings.rs", r#"podssh_ws::resolve::parse_pins(text).map_err(|e| format!("{at}: RelayAddr {text}: {e}"))?;"#),
    ("ssh/cloud/aws.rs", r#"let mut json: Value = serde_json::from_str(text).map_err(|e| format!("it is not JSON: {e}"))?;"#),
    ("ssh/cloud/google.rs", r#"let mut json: Value = serde_json::from_str(trimmed).map_err(|e| format!("it is not a token, nor JSON: {e}"))?;"#),
    ("ssh/cloud/google.rs", r#"let key = KeyPair::from_pkcs8(&der).map_err(|e| format!("aws-lc-rs refused its private_key: {e}"))?;"#),
    ("ssh/cloud/google.rs", r#"let words = podssh_ws::text::one_line(&format!("{error} {said}"));"#),
    ("ssh/resolve.rs", r#".ok_or_else(|| format!("-e {e}: expected none, a character or ^X"))?,"#),
];

/// Lines of `crates/podssh-ssh/src/` that show a value which is no I/O error, as (file under its `src/`, the
/// line without its indent): here the escape character of `~?`'s help, named `e`.
#[rustfmt::skip]
const SSH_NOT_IO: &[(&str, &str)] = &[
    ("escape.rs", r#"text.push_str(&format!(" {e}{}   - {words}\n", *key as char));"#),
    ("escape.rs", r#"text.push_str(&format!(" {e}{e}   - send the escape character by typing it twice\n"));"#),
];

/// Modules of `crates/podssh-ssh/src/` that hold no I/O error at all, as (file under its `src/`, why). Each
/// takes bytes or text already in memory and gives a key, a signature, a certificate or a parser's fault.
#[rustfmt::skip]
const SSH_EXEMPT: &[(&str, &str)] = &[
    ("convert.rs", "key formats (PuTTY, PEM, DER) converted in memory: ssh-key, pkcs8 and base64 faults"),
    ("rsa_key.rs", "RSA keys built and read in memory: aws-lc-rs and ssh-key faults"),
    ("sshsig_cert.rs", "the signature of a certificate, parsed from bytes in memory"),
    ("policy/file.rs", "the text of a policy file, already read, parsed: UTF-8 and JSON faults"),
    ("tpm/ssh.rs", "a TPM key's blob turned into an SSH public key"),
    ("sk/format.rs", "security-key blobs, key files and CBOR parsed in memory"),
    ("sk/flow.rs", "a security key's CBOR answer parsed in memory"),
];

/// Words of a line that reaches a file, a socket, a stream or an agent: an exempt module has none.
const IO_WORDS: &[&str] = &[
    "std::fs",
    "tokio::fs",
    "std::io",
    "tokio::io",
    "std::net",
    "tokio::net",
    "AsyncRead",
    "AsyncWrite",
    "File::",
    "UnixStream",
    "TcpStream",
    "AgentClient",
    "request_identities",
    "sign_request",
    "io::Error",
];

/// Whether `line` names a way to reach a file, a socket, a stream or an agent.
fn touches_io(line: &str) -> bool {
    IO_WORDS.iter().any(|w| line.contains(w))
}

/// One crate that the scan reads: its sources, its table of lines and its exempt modules.
struct Tree {
    name: &'static str,
    /// The sources, from the manifest directory of this test's crate.
    src: &'static str,
    not_io: &'static [(&'static str, &'static str)],
    exempt: &'static [(&'static str, &'static str)],
}

const TREES: &[Tree] = &[
    Tree { name: "podssh-cli", src: "src", not_io: NOT_IO, exempt: &[] },
    Tree { name: "podssh-ssh", src: "../podssh-ssh/src", not_io: SSH_NOT_IO, exempt: SSH_EXEMPT },
];

/// Whether `line` of `rel` builds a failure of the file commands, whose constructor `Failed::new` takes
/// Rust's suffix off the message itself (`cp/transfer.rs`).
fn sunk(tree: &Tree, rel: &str, line: &str) -> bool {
    tree.name == "podssh-cli"
        && rel.starts_with("cp/")
        && (line.contains("Failed::new(") || line.contains("failed(Fault::"))
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

/// The code lines of each source file of `tree` outside its test code, as (file under its `src/`, line
/// number, the line without its indent); comment lines are not code.
fn code_lines(tree: &Tree) -> Vec<(String, usize, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join(tree.src);
    let mut files = Vec::new();
    sources(&src, &mut files);
    let mut found = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let in_test = test_blocks(&lines);
        for (i, line) in lines.iter().enumerate() {
            let shown = line.trim();
            if !in_test[i] && !shown.starts_with("//") {
                found.push((rel.clone(), i + 1, shown.to_string()));
            }
        }
    }
    found
}

/// Each hit of the scan in `tree`, as (file under its `src/`, line number, the line without its indent).
fn hits(tree: &Tree) -> Vec<(String, usize, String)> {
    let mut found = code_lines(tree);
    found.retain(|(rel, _, line)| shows_display(line) && !sunk(tree, rel, line));
    found
}

#[test]
fn no_io_error_reaches_a_line_by_its_display() {
    for tree in TREES {
        let all = hits(tree);
        let exempt = |file: &str| tree.exempt.iter().any(|(f, _)| *f == file);
        let found: Vec<_> = all.iter().filter(|(file, _, _)| !exempt(file)).collect();
        assert!(
            all.len() >= tree.not_io.len() + tree.exempt.len(),
            "{}: the scan found {} lines: it reads nothing",
            tree.name,
            all.len()
        );
        let unlisted: Vec<String> = found
            .iter()
            .filter(|(file, _, line)| !tree.not_io.iter().any(|(f, l)| f == file && l == line))
            .map(|(file, at, line)| format!("{}/{file}:{at}: {line}", tree.name))
            .collect();
        assert!(
            unlisted.is_empty(),
            "a user line shows an error by its Display, which keeps Rust's \"(os error N)\": use \
             podssh_ws::text::said(&e), or list the line in its NOT_IO table if the value is no I/O error \
             (a whole module of codecs goes in the exempt list, with why):\n{}",
            unlisted.join("\n")
        );
        let gone: Vec<String> = tree
            .not_io
            .iter()
            .filter(|(f, l)| !found.iter().any(|(file, _, line)| file == f && line == l))
            .map(|(f, l)| format!("{}/{f}: {l}", tree.name))
            .collect();
        assert!(
            gone.is_empty(),
            "a NOT_IO table lists lines that the scan no longer finds; remove them:\n{}",
            gone.join("\n")
        );
    }
}

/// An exempt module is live (it still has a hit, so the exemption is not stale), has a reason, and holds
/// no line that reaches a file, a socket, a stream or an agent: it is then no place for an I/O error.
#[test]
fn an_exempt_module_is_a_live_codec_with_no_io() {
    for tree in TREES {
        let all = hits(tree);
        let code = code_lines(tree);
        for (module, why) in tree.exempt {
            assert!(!why.trim().is_empty(), "{}/{module} is exempt with no reason", tree.name);
            assert!(
                code.iter().any(|(file, _, _)| file == module),
                "{}/{module} is exempt but is no source file here: remove it",
                tree.name
            );
            assert!(
                all.iter().any(|(file, _, _)| file == module),
                "{}/{module} is exempt but has no hit: remove it",
                tree.name
            );
            let io: Vec<String> = code
                .iter()
                .filter(|(file, _, line)| file == module && touches_io(line))
                .map(|(_, at, line)| format!("{}/{module}:{at}: {line}", tree.name))
                .collect();
            assert!(
                io.is_empty(),
                "an exempt module reaches I/O, so its errors may carry \"(os error N)\": take it off the exempt \
                 list and convert its lines:\n{}",
                io.join("\n")
            );
        }
        let mut names: Vec<&str> = tree.exempt.iter().map(|(f, _)| *f).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), tree.exempt.len(), "{} lists a module twice", tree.name);
    }
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

/// The guard of an exempt module sees each way to reach I/O and no codec's word.
#[test]
fn the_guard_of_an_exempt_module_sees_io_and_only_io() {
    for line in [
        "use std::fs;",
        "let file = File::open(path)?;",
        "fn run(r: &mut (impl AsyncRead + Unpin)) {}",
        "agent.request_identities().await",
        "fn f() -> Result<(), std::io::Error> {",
        "let s = UnixStream::connect(p)?;",
    ] {
        assert!(touches_io(line), "{line}");
    }
    for line in [
        "let blob = key.key_data().encode_vec().map_err(|e| e.to_string())?;",
        "let key = PublicKey::from_bytes(&blob)?;",
        "let doc: Value = serde_json::from_str(value)?;",
    ] {
        assert!(!touches_io(line), "{line}");
    }
}

/// The scan reaches each source file of each crate, and no file of tests.
#[test]
fn the_scan_reaches_the_whole_crate() {
    let reached: [(&Tree, &[&str]); 2] = [
        (
            &TREES[0],
            &["node.rs", "ssh/config.rs", "cp/words.rs", "doctor/mod.rs", "run_cmd/mod.rs", "keygen.rs", "mcp/mod.rs"],
        ),
        (
            &TREES[1],
            &[
                "session.rs",
                "keys.rs",
                "known_hosts.rs",
                "server/mod.rs",
                "server/pty.rs",
                "tpm/mod.rs",
                "zmodem/files.rs",
            ],
        ),
    ];
    for (tree, expected) in reached {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join(tree.src);
        let mut files = Vec::new();
        sources(&src, &mut files);
        let names: Vec<String> =
            files.iter().map(|p| p.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/")).collect();
        for rel in expected {
            assert!(names.iter().any(|n| n == rel), "{}/{rel} is not scanned", tree.name);
        }
        assert!(
            names.iter().all(|n| !n.ends_with("_tests.rs") && !n.ends_with("/tests.rs")),
            "{}: a test file is scanned",
            tree.name
        );
    }
}

/// The exemption covers the constructor's own lines and no other line of `cp/`, and only in podssh-cli.
#[test]
fn only_the_failed_constructor_of_cp_is_a_sink() {
    let cli = &TREES[0];
    assert!(sunk(cli, "cp/bysftp.rs", r#"failed(Fault::NoInput, format!("{source}: {e}"))"#));
    assert!(sunk(cli, "cp/chunks.rs", r#".map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;"#));
    assert!(!sunk(cli, "cp/mod.rs", r#"let why = format!("could not start the async runtime: {e}");"#));
    assert!(!sunk(cli, "doctor/mod.rs", r#"Failed::new(Fault::CantCreate, format!("{e}"))"#));
    assert!(!sunk(&TREES[1], "cp/bysftp.rs", r#"Failed::new(Fault::NoInput, format!("{e}"))"#));
}
