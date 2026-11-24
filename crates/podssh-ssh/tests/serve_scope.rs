//! Each pty child of `podssh serve` in a transient scope of its own where
//! systemd is there (T-122): the command line of the move, the reading of
//! `/proc/PID/cgroup`, the probe and each of its fallbacks; then, with
//! russh's client over a pipe, a session whose move fails or hangs runs
//! where serve is, with one line, within the bound; and, on a host whose
//! user manager answers, a child on a pty is in its scope.

#![cfg(target_os = "linux")]

mod cleanup;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::PrivateKeyWithHashAlg;
use podssh_ssh::russh::{self, client, ChannelMsg};
use podssh_ssh::server::scope::{self, Tool};
use podssh_ssh::server::{self, pty, Authorized, PtyMode, Say, Settings};

/// A bound on each wait of a test.
const WAIT: Duration = Duration::from_secs(30);

/// A directory of this test, removed when it ends.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-scope-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir.canonicalize().unwrap()
}

/// An executable file `name` in `dir` with `text`.
fn program(dir: &Path, name: &str, text: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn the_call_asks_for_one_scope_holding_the_child() {
    let args = scope::call_args("podssh-serve-7-1.scope", 4242);
    #[rustfmt::skip]
    let want = [
        "--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
        "podssh-serve-7-1.scope", "fail", "2", "PIDs", "au", "1", "4242",
        "Description", "s", "podssh serve: one session", "0",
    ];
    assert_eq!(args, want);
    let (a, b) = (scope::unit_name(), scope::unit_name());
    assert_ne!(a, b, "each session its own name");
    let prefix = format!("podssh-serve-{}-", std::process::id());
    assert!(a.starts_with(&prefix) && a.ends_with(".scope"), "{a}");
}

#[test]
fn the_cgroup_file_names_the_scope_or_not() {
    let unit = "podssh-serve-7-1.scope";
    #[rustfmt::skip]
    let cases: &[(&str, bool)] = &[
        ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/podssh-serve-7-1.scope\n", true),
        ("12:pids:/user.slice\n1:name=systemd:/user.slice/user@1000.service/podssh-serve-7-1.scope\n0::/x\n", true),
        ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/podssh-serve.service\n", false),
        ("0::/user.slice/podssh-serve-7-1.scope/child\n", false),
        ("0::/user.slice/podssh-serve-7-11.scope\n", false),
        ("", false),
    ];
    for (text, want) in cases {
        assert_eq!(scope::in_unit(text, unit), *want, "{text:?}");
    }
}

#[test]
fn the_probe_passes_only_a_manager_that_runs() {
    let dir = scratch("probe");
    let booted = dir.join("booted");
    std::fs::create_dir(&booted).unwrap();
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let busctl = program(&bin, "busctl", "#!/bin/sh\nexit 0\n");
    program(&bin, "systemctl", "#!/bin/sh\nexit 0\n");
    let only_busctl = dir.join("only");
    std::fs::create_dir(&only_busctl).unwrap();
    program(&only_busctl, "busctl", "#!/bin/sh\nexit 0\n");
    let says = |words: &'static str| move |_: &str, _: &[&str]| -> scope::Ran { Ok(words.to_string()) };
    let path = bin.as_os_str();
    let none = dir.join("none");
    #[rustfmt::skip]
    let cases: Vec<(&str, &Path, Option<&OsStr>, Box<dyn Fn(&str, &[&str]) -> scope::Ran>, Result<(), &str>)> = vec![
        ("no systemd", &none, Some(path), Box::new(says("running")), Err("not this host's service manager")),
        ("no busctl", &booted, Some(dir.as_os_str()), Box::new(says("running")), Err("no busctl on PATH")),
        ("no systemctl", &booted, Some(only_busctl.as_os_str()), Box::new(says("running")), Err("no systemctl on PATH")),
        ("no PATH", &booted, None, Box::new(says("running")), Err("no busctl on PATH")),
        ("no answer", &booted, Some(path), Box::new(|_: &str, _: &[&str]| Err("systemctl: timed out".to_string())), Err("timed out")),
        ("offline", &booted, Some(path), Box::new(says("offline\n")), Err("\"offline\"")),
        ("silent", &booted, Some(path), Box::new(says("")), Err("said nothing")),
        ("running", &booted, Some(path), Box::new(says("running\n")), Ok(())),
        ("degraded", &booted, Some(path), Box::new(says("degraded\n")), Ok(())),
    ];
    for (what, root, path_var, run, want) in &cases {
        let got = scope::probe_with(root, *path_var, run.as_ref());
        match (got, want) {
            (Ok(tool), Ok(())) => assert_eq!(tool, Tool { busctl: busctl.clone() }, "{what}"),
            (Err(why), Err(part)) => assert!(why.contains(part), "{what}: {why}"),
            (got, want) => panic!("{what}: {got:?}, not {want:?}"),
        }
    }
    let relative = std::env::join_paths(["relative/bin"]).unwrap();
    assert_eq!(
        scope::on_path(Some(relative.as_os_str()), "busctl"),
        None,
        "a relative directory of PATH is passed over"
    );
    program(&dir, "plain", "data");
    std::fs::set_permissions(dir.join("plain"), std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    assert_eq!(scope::on_path(Some(dir.as_os_str()), "plain"), None, "a file that does not run");
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Run `command` on a pty of a server whose scope's tool is `tool`: its
/// output, how long it took, and serve's lines.
async fn on_a_pty(tool: Option<Tool>, command: &str) -> (String, Duration, Vec<String>) {
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = keygen::generate(KeyKind::Ed25519, "test").unwrap();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    let say = Say(Arc::new(move |line: &str| kept.lock().unwrap().push(line.to_string())));
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = Settings {
        base_env: Some(vec![("PATH".into(), path)]),
        shell: Some("/bin/sh".into()),
        pty: PtyMode::No,
        scope: tool,
        say: Some(say),
        ..Settings::default()
    };
    let host = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    tokio::spawn(server::serve_with(far, host, Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    let started = Instant::now();
    channel.exec(true, command).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(WAIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await;
    let took = started.elapsed();
    let said = lines.lock().unwrap().clone();
    (String::from_utf8_lossy(&out).into_owned(), took, said)
}

fn have_pty() -> bool {
    match pty::open() {
        Ok(_) => true,
        Err(why) => {
            eprintln!("did not run: no pty here: {why}");
            false
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_move_that_fails_or_hangs_leaves_the_session_where_serve_is() {
    if !have_pty() {
        return;
    }
    let dir = scratch("fallback");
    let refusing = program(&dir, "busctl-refuses", "#!/bin/sh\necho 'Access denied' >&2\nexit 1\n");
    let (out, _, said) = on_a_pty(Some(Tool { busctl: refusing }), "echo RAN-HERE").await;
    assert!(out.contains("RAN-HERE"), "the session runs: {out:?}");
    assert!(said.iter().any(|l| l.contains("stays in serve's own cgroup")), "one line: {said:?}");

    // A tool that hangs: the child goes on once the call's bound passes.
    let hanging = program(&dir, "busctl-hangs", "#!/bin/sh\nexec sleep 10\n");
    let (out, took, said) = on_a_pty(Some(Tool { busctl: hanging }), "echo RAN-HERE").await;
    assert!(out.contains("RAN-HERE"), "the session runs: {out:?}");
    let bound = scope::CALL_WAIT + scope::SETTLE + Duration::from_secs(2);
    assert!(took < bound, "within the bound: {took:?}");
    assert!(said.iter().any(|l| l.contains("stays in serve's own cgroup")), "one line: {said:?}");

    // No tool, as on a host with no systemd: no line, the session as before.
    let (out, _, said) = on_a_pty(None, "echo RAN-HERE").await;
    assert!(out.contains("RAN-HERE") && said.is_empty(), "{out:?} {said:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn where_the_user_manager_answers_the_child_is_in_its_scope() {
    if !have_pty() {
        return;
    }
    let tool = match scope::probe() {
        Ok(tool) => tool,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let (out, _, said) = on_a_pty(Some(tool), "cat /proc/self/cgroup").await;
    let prefix = format!("/podssh-serve-{}-", std::process::id());
    assert!(out.contains(&prefix) && out.contains(".scope"), "{out:?} {said:?}");
}
