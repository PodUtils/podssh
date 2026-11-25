//! `--result-file FILE` (T-054) against the test's SSH server, with
//! `--direct`: the exit, the remote status or signal, how the session ended,
//! the class of a failure and the bytes, in one JSON object, while stdout and
//! stderr stay as they are. The server's `exit N` prints `out` and `err!`,
//! `kill NAME` ends with a signal, `cat` echoes, the socket `/echo` of `-W`
//! sends back what it gets, a user `key-...` needs a key that the test
//! does not have, and `cut N` cuts the link after the status (T-461).
//! A run of `-N` lists its forwards also when it fails before its link, and
//! ends at Ctrl-C as `interrupted`, with 130 and its file (T-866).

mod cleanup;
mod ssh_harness;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

/// A run of `podssh ssh --direct --result-file` with the flags `flags`, as
/// `user` on `port`, with `input`: the exit code, stdout, stderr, and the
/// object of the file.
fn run(dir: &Path, port: u16, flags: &[&str], user: &str, command: &[&str], input: &[u8]) -> Ran {
    let result = dir.join(format!("result-{}.json", rand_tag()));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]);
    cmd.args(["-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(flags).arg("--result-file").arg(&result).arg(format!("{user}@127.0.0.1")).args(command);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let text = std::fs::read_to_string(&result).unwrap_or_else(|e| panic!("no result file ({e}): {err}"));
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
    (out.status.code(), out.stdout, err, value)
}

type Ran = (Option<i32>, Vec<u8>, String, Value);

fn rand_tag() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::Relaxed).to_string()
}

fn server(tag: &str) -> (PathBuf, u16, tokio::runtime::Runtime) {
    let dir = std::env::temp_dir().join(format!("podssh-result-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (dir, port, runtime)
}

/// Each line of the object but the time, which a run cannot know before.
fn shape(mut value: Value) -> Value {
    assert!(value["duration_ms"].as_u64().is_some(), "{value}");
    value.as_object_mut().unwrap().remove("duration_ms");
    value
}

#[test]
fn the_result_holds_the_status_the_signal_and_the_bytes() {
    let (dir, port, _runtime) = server("ends");
    let (code, out, err, r) = run(&dir, port, &[], "u", &["exit", "3"], b"");
    assert_eq!((code, out.as_slice()), (Some(3), &b"out\n"[..]), "{err}");
    assert!(err.contains("err!\n"), "stderr stays as it is: {err}");
    let bytes = json!({ "stdin": 0, "stdout": 4, "stderr": 5 });
    let want = json!({ "schema": 1, "exit": 3, "status": 3, "signal": null, "end": "status", "failure": null,
        "bytes": bytes, "relay": null });
    assert_eq!(shape(r), want);

    let (code, _, err, r) = run(&dir, port, &[], "u", &["kill", "TERM"], b"");
    assert_eq!(code, Some(143), "{err}");
    assert_eq!((&r["status"], &r["end"]), (&Value::Null, &json!("signal")), "{r}");
    assert_eq!(r["signal"], json!({ "name": "TERM", "core_dumped": false }));
    let (_, _, _, r) = run(&dir, port, &[], "u", &["kill", "SEGV"], b"");
    assert_eq!((r["exit"].as_i64(), &r["signal"]), (Some(139), &json!({ "name": "SEGV", "core_dumped": true })));

    let input = vec![0x61u8; 100_000];
    let (code, out, err, r) = run(&dir, port, &[], "u", &["cat"], &input);
    assert_eq!((code, out.len()), (Some(0), input.len()), "{err}");
    assert_eq!(r["bytes"], json!({ "stdin": 100_000, "stdout": 100_000, "stderr": 0 }));
}

/// A link cut after the remote status and before the output's end (T-461,
/// GitHub #84, whose file held `"exit":0`): `lost` and 255, the status kept
/// beside them for a reader; with the EOF before the cut, the status holds.
#[test]
fn a_cut_after_the_status_is_lost_with_the_status_kept() {
    let (dir, port, _runtime) = server("cut");
    let (code, out, err, r) = run(&dir, port, &[], "u", &["cut", "1000000"], b"");
    assert_eq!(code, Some(255), "{err}");
    assert!(out.len() <= 1_000_000, "{}", out.len());
    let got = (&r["exit"], &r["status"], &r["end"], &r["failure"]);
    assert_eq!(got, (&json!(255), &json!(0), &json!("lost"), &json!("session")), "{r}");
    let (code, out, err, r) = run(&dir, port, &[], "u", &["cut-eof", "1000000"], b"");
    assert_eq!((code, out.len()), (Some(0), 1_000_000), "{err}");
    let got = (&r["exit"], &r["status"], &r["end"], &r["failure"]);
    assert_eq!(got, (&json!(0), &json!(0), &json!("status"), &Value::Null), "{r}");
}

/// A failure before the session: its class, and the end `failed`.
#[test]
fn a_failure_has_its_class() {
    let (dir, port, _runtime) = server("fail");
    let (code, _, err, r) = run(&dir, port, &[], "key-x", &["true"], b"");
    assert_eq!(code, Some(255), "{err}");
    assert_eq!((&r["end"], &r["failure"], &r["status"]), (&json!("failed"), &json!("auth"), &Value::Null), "{r}");
    // A port where nothing listens.
    // Port 1 of the loopback: a port freed here could be bound by a test
    // that runs beside this one before the dial.
    let closed: u16 = 1;
    let (code, _, err, r) = run(&dir, closed, &[], "u", &["true"], b"");
    assert_eq!(code, Some(255), "{err}");
    assert_eq!((&r["end"], &r["failure"]), (&json!("failed"), &json!("connect")), "{r}");
}

/// `-W` carries stdin and stdout with no session: its bytes, and no end. A
/// socket that the server refuses is the class `forward`. The forward is
/// listed with its state word (T-840): `up`, or `refused` with the reason.
#[test]
fn a_stdio_forward_has_its_bytes_and_no_session() {
    let (dir, port, _runtime) = server("stdio");
    let input = vec![0x62u8; 10_000];
    let (code, out, err, mut r) = run(&dir, port, &["-W", "/echo"], "u", &[], &input);
    assert_eq!((code, out.len()), (Some(0), input.len()), "{err}");
    let forwards = r.as_object_mut().unwrap().remove("forwards").unwrap_or_else(|| panic!("no forwards: {err}"));
    let w = &forwards[0];
    assert_eq!((&w["name"], &w["state"], &w["reason"]), (&json!("-W /echo"), &json!("up"), &Value::Null), "{w}");
    assert_eq!((&w["connections"], &w["bytes_up"], &w["bytes_down"]), (&json!(1), &json!(10_000), &json!(10_000)));
    let bytes = json!({ "stdin": 10_000, "stdout": 10_000, "stderr": 0 });
    let want = json!({ "schema": 1, "exit": 0, "status": null, "signal": null, "end": null, "failure": null,
        "bytes": bytes, "relay": null });
    assert_eq!(shape(r), want);
    let (code, _, err, r) = run(&dir, port, &["-W", "/elsewhere"], "u", &[], b"");
    assert_eq!(code, Some(255), "{err}");
    assert_eq!((&r["end"], &r["failure"]), (&json!("failed"), &json!("forward")), "{r}");
    let w = &r["forwards"][0];
    assert_eq!((&w["name"], &w["state"], &w["failed"]), (&json!("-W /elsewhere"), &json!("refused"), &json!(1)), "{r}");
    assert!(w["reason"].as_str().is_some_and(|reason| !reason.is_empty()), "the server's reason: {r}");
}

/// `-` is refused, as stdout is the command's; a usage error is written.
#[test]
fn dash_is_refused_and_a_usage_error_is_a_result() {
    let dir = std::env::temp_dir().join(format!("podssh-result-usage-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let podssh = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").stdin(Stdio::null());
        cmd
    };
    let out = podssh().args(["ssh", "--result-file", "-", "host"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--result-file -: stdout carries the command's output"));
    let file = dir.join("usage.json");
    let out = podssh().args(["ssh", "-p", "notaport", "--result-file"]).arg(&file).arg("host").output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!((&r["exit"], &r["end"], &r["failure"]), (&json!(64), &json!("failed"), &json!("usage")), "{r}");
}

/// A loopback port that nothing listens on now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A run of `-N` that fails before its link lists each forward of its
/// command line, `bound`, as its listener is or its request is asked for
/// (T-866); before, the file had no `forwards`.
#[test]
fn a_run_that_fails_before_its_link_lists_its_forwards() {
    let (dir, _port, _runtime) = server("unlinked");
    // Port 1: a freed port could be bound by a test beside this one.
    let closed: u16 = 1;
    let local = format!("{}:127.0.0.1:9", free_port());
    let remote = "0:127.0.0.1:9";
    let (code, _, err, r) = run(&dir, closed, &["-N", "-L", &local, "-R", remote], "u", &[], b"");
    assert_eq!(code, Some(255), "{err}");
    assert_eq!((&r["end"], &r["failure"]), (&json!("failed"), &json!("connect")), "{r}");
    let forwards = r["forwards"].as_array().unwrap_or_else(|| panic!("no forwards: {r}"));
    assert_eq!(forwards.len(), 2, "{r}");
    for (f, spec) in forwards.iter().zip([local.as_str(), remote]) {
        let name = f["name"].as_str().unwrap_or_default();
        assert!(name.ends_with(spec), "{spec}: {f}");
        assert_eq!((&f["state"], &f["closed"], &f["connections"]), (&json!("bound"), &json!(false), &json!(0)), "{f}");
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, Instant};

    const LIMIT: Duration = Duration::from_secs(30);

    /// An echo server on the loopback, for the target of `-L`.
    fn echo() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let (mut from, mut to) = (stream.try_clone().unwrap(), stream);
                    let _ = std::io::copy(&mut from, &mut to);
                });
            }
        });
        port
    }

    /// Whether bytes go through the listener at `port` and come back: the
    /// forward is up on a link that logged in.
    fn echoes(port: u16) -> bool {
        let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return false };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        if std::io::Write::write_all(&mut stream, b"ping").is_err() {
            return false;
        }
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).is_ok() && &back == b"ping"
    }

    /// Ctrl-C ends a run of `-N` (T-866): before, SIGINT's default action
    /// killed podssh, and no file was written. Now the file says
    /// `interrupted`, with no failure, and podssh exits 130, as a run with
    /// no pty does at Ctrl-C.
    #[test]
    fn ctrl_c_ends_n_as_interrupted_with_its_file() {
        let (dir, port, _runtime) = server("n-int");
        let (target, local) = (echo(), free_port());
        let spec = format!("{local}:127.0.0.1:{target}");
        let result = dir.join("n-int.json");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]);
        cmd.args(["-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
        cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
        cmd.args(["-N", "-L", &spec, "--result-file"]).arg(&result).arg("u@127.0.0.1");
        cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", &dir);
        for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
            cmd.env_remove(name);
        }
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let deadline = Instant::now() + LIMIT;
        while !echoes(local) {
            if Instant::now() > deadline || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                panic!("the forward of -N never carried");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // SAFETY: kill sends a signal to podssh's process and does nothing else.
        let sent = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
        assert_eq!(sent, 0, "kill: {}", std::io::Error::last_os_error());
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("podssh -N did not end at SIGINT");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(status.code(), Some(130), "{status:?}");
        let text = std::fs::read_to_string(&result).unwrap_or_else(|e| panic!("no result file: {e}"));
        let r: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
        assert_eq!((&r["exit"], &r["end"], &r["failure"]), (&json!(130), &json!("interrupted"), &Value::Null), "{r}");
        let f = &r["forwards"][0];
        assert!(f["name"].as_str().is_some_and(|name| name.ends_with(&spec)), "{r}");
        assert_eq!(f["state"], json!("up"), "{r}");
    }
}
