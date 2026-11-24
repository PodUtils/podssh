//! The audit log of `podssh serve` (T-116), with russh's client over a
//! pipe: each line is one JSON object of PodUtils' log schema, chained; a
//! login, a session with its exit status and its bytes, a refused key and
//! a refused forward each have their line; a command's words are written
//! only with `--audit-commands`; a log that cannot be written stops no
//! session. The same through OpenSSH's client and `podssh serve --stdio`:
//! `podssh-cli`'s `tests/serve_audit_openssh.rs`.

#![cfg(unix)]

mod cleanup;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg, Disconnect};
use podssh_ssh::server::audit::{chain, Audit};
use podssh_ssh::server::{self, Authorized, Settings};
use serde_json::Value;

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

/// The marker of a command's words, which no line may hold by default.
const MARKER: &str = "SECRET-MARKER";

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-audit-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

fn settings(audit: &Arc<Audit>) -> Settings {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path)];
    Settings { base_env: Some(base), audit: Some(audit.clone()), ..Settings::default() }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A server for `listed`, and the client that tries `login` with it; the
/// server's task, which ends with the connection.
async fn connect(
    settings: Settings,
    listed: &PrivateKey,
    login: PrivateKey,
) -> (client::Handle<Trusting>, bool, tokio::task::JoinHandle<Result<(), String>>) {
    let (near, far) = tokio::io::duplex(1 << 16);
    let mut authorized = Authorized::new();
    authorized.add(listed.public_key().key_data().clone());
    let served = tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    let ok = handle.authenticate_publickey("tester", login).await.unwrap().success();
    (handle, ok, served)
}

/// Run `command`, and the status that came back.
async fn exec(handle: &client::Handle<Trusting>, command: &str) -> Option<u32> {
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut status = None;
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("the channel closes in time");
    status
}

/// Leave, wait for the server's end, and read each line written.
async fn leave(
    handle: client::Handle<Trusting>,
    served: tokio::task::JoinHandle<Result<(), String>>,
    audit: &Arc<Audit>,
) -> Vec<Value> {
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    drop(handle);
    let _ = tokio::time::timeout(LIMIT, served).await.expect("the server ends");
    audit.stopped("ok");
    lines(audit.path())
}

fn lines(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"))).collect()
}

/// The lines of `event`.
fn of<'a>(lines: &'a [Value], event: &str) -> Vec<&'a Value> {
    lines.iter().filter(|l| l["event"] == event).collect()
}

fn holds(path: &Path) {
    let file = std::fs::File::open(path).unwrap();
    let verdict = chain::verify(&mut std::io::BufReader::new(file)).unwrap();
    assert!(verdict.holds() && verdict.unfinished.is_empty(), "{verdict:?}");
}

/// A session's lines, with and without `--audit-commands`: the words of
/// its command in the file once only with the flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_is_recorded_and_its_words_only_when_asked() {
    for (commands, count) in [(false, 0), (true, 1)] {
        let dir = scratch("session");
        let audit = Audit::open(&dir.join("audit.log"), commands, None).unwrap();
        audit.started("test");
        let login = key();
        let who = podssh_ssh::known_hosts::fingerprint(login.public_key());
        let (handle, ok, served) = connect(settings(&audit), &login, login.clone()).await;
        assert!(ok, "the listed key logs in");
        assert_eq!(exec(&handle, &format!("echo {MARKER}")).await, Some(0));
        let lines = leave(handle, served, &audit).await;
        for line in &lines {
            assert_eq!(line["schema"], 1, "{line}");
            assert!(line["time"].as_str().is_some_and(|t| t.ends_with('Z')), "{line}");
            assert!(line["fields"]["prev"].as_str().is_some_and(|p| p.len() == 64), "{line}");
        }
        let accepted = of(&lines, "serve.auth.accepted");
        assert_eq!(accepted.len(), 1, "{lines:?}");
        assert_eq!(accepted[0]["fields"]["key"], Value::from(who), "{lines:?}");
        assert_eq!(accepted[0]["fields"]["user"], "tester", "{lines:?}");
        let start = of(&lines, "serve.session.start");
        assert_eq!(start.len(), 1, "{lines:?}");
        assert_eq!(start[0]["fields"]["request"], "exec");
        let end = of(&lines, "serve.session.end");
        assert_eq!(end.len(), 1, "{lines:?}");
        assert_eq!(end[0]["fields"]["exit_status"], 0, "{lines:?}");
        let out = end[0]["fields"]["bytes_out"].as_u64().unwrap_or(0);
        assert!(out >= (MARKER.len() + 1) as u64, "the bytes of the output: {lines:?}");
        assert_eq!(of(&lines, "serve.conn.open").len(), 1);
        assert_eq!(of(&lines, "serve.conn.close").len(), 1);
        let text = std::fs::read_to_string(audit.path()).unwrap();
        assert_eq!(text.matches(MARKER).count(), count, "--audit-commands {commands}: {text}");
        holds(audit.path());
    }
}

/// A key that no line lists is refused, with its fingerprint and why; a
/// forward that `--no-forwarding` refuses is said with its target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_key_and_a_refused_forward_have_their_lines() {
    let dir = scratch("refused");
    let audit = Audit::open(&dir.join("audit.log"), false, None).unwrap();
    audit.started("test");
    let (listed, stranger) = (key(), key());
    let who = podssh_ssh::known_hosts::fingerprint(stranger.public_key());
    let (handle, ok, served) = connect(settings(&audit), &listed, stranger).await;
    assert!(!ok, "a key that is not listed");
    let lines = leave(handle, served, &audit).await;
    let refused = of(&lines, "serve.auth.refused");
    assert!(!refused.is_empty(), "{lines:?}");
    assert_eq!(refused[0]["level"], "warn");
    assert_eq!(refused[0]["fields"]["key"], Value::from(who));
    assert_eq!(refused[0]["fields"]["reason"], "not an authorized key");

    let audit = Audit::open(&dir.join("audit2.log"), false, None).unwrap();
    audit.started("test");
    let login = key();
    let closed = Settings { no_forwarding: true, ..settings(&audit) };
    let (handle, ok, served) = connect(closed, &login, login.clone()).await;
    assert!(ok);
    let open = handle.channel_open_direct_tcpip("127.0.0.1", 2203, "127.0.0.1", 1);
    assert!(tokio::time::timeout(LIMIT, open).await.expect("an answer").is_err(), "refused");
    let lines = leave(handle, served, &audit).await;
    let refused = of(&lines, "serve.forward.refused");
    assert_eq!(refused.len(), 1, "{lines:?}");
    assert_eq!(refused[0]["fields"]["target"], "127.0.0.1:2203");
    assert!(refused[0]["fields"]["reason"].as_str().is_some_and(|r| r.contains("--no-forwarding")), "{lines:?}");
    holds(audit.path());
}

/// A log that can no longer be written stops no session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_log_that_cannot_be_written_stops_no_session() {
    let dir = scratch("broken");
    let path = dir.join("audit.log");
    let audit = Audit::open(&path, false, None).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let login = key();
    let (handle, ok, served) = connect(settings(&audit), &login, login.clone()).await;
    assert!(ok);
    assert_eq!(exec(&handle, "exit 3").await, Some(3));
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    drop(handle);
    let ended = tokio::time::timeout(LIMIT, served).await.expect("the server ends").unwrap();
    assert_eq!(ended, Ok(()));
}
