//! A command and a shell of `podssh serve` (T-108), with russh's client over
//! a pipe: the exit status, stdout and stderr apart, and the end in its
//! order (`exit-status` or `exit-signal` before EOF and close); a signal
//! request to the command; stdin back whole; the environment filter, and no
//! credential of serve's in the child's; a pty refused where no master
//! opens, with the command run without one; a missing shell named on the channel's stderr (T-222); a
//! background job that holds the pipes does not hold the end. The same
//! against OpenSSH's client: `podssh-cli`'s `tests/serve_openssh.rs`.

#![cfg(unix)]

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg, Sig};
use podssh_ssh::server::{self, Authorized, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// serve's environment in these tests: this host's PATH, and a credential
/// that no child may see.
fn base_env() -> Vec<(OsString, OsString)> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    vec![
        ("PATH".into(), path),
        ("PODSSH_RELAY_TOKEN".into(), "planted-token-of-serve".into()),
        ("SERVE_OWN".into(), "kept".into()),
    ]
}

fn settings() -> Settings {
    Settings { base_env: Some(base_env()), ..Settings::default() }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a new server with `settings`.
async fn connect(settings: Settings) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// What a channel gave until its close: stdout, stderr, and the order of
/// the messages that end it.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    err: Vec<u8>,
    replies: Vec<bool>,
    status: Option<u32>,
    signal: Option<String>,
    order: Vec<&'static str>,
}

async fn read_to_close(channel: &mut russh::Channel<client::Msg>) -> Seen {
    let mut seen = Seen::default();
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    seen.out.extend_from_slice(&data);
                    seen.order.push("data");
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    seen.err.extend_from_slice(&data);
                    seen.order.push("data");
                }
                ChannelMsg::Success => seen.replies.push(true),
                ChannelMsg::Failure => seen.replies.push(false),
                ChannelMsg::ExitStatus { exit_status } => {
                    seen.status = Some(exit_status);
                    seen.order.push("exit");
                }
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    seen.signal = Some(podssh_ssh::signals::name(&signal_name));
                    seen.order.push("exit");
                }
                ChannelMsg::Eof => seen.order.push("eof"),
                ChannelMsg::Close => {
                    seen.order.push("close");
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the channel closes in time");
    seen
}

async fn run(settings: Settings, command: &str) -> Seen {
    let handle = connect(settings).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    read_to_close(&mut channel).await
}

/// The end in its order: each byte, then one exit message, then EOF, then
/// close.
fn ended_in_order(seen: &Seen) {
    let at = |what: &str| seen.order.iter().position(|o| *o == what);
    let last_data = seen.order.iter().rposition(|o| *o == "data");
    let (exit, eof, close) = (at("exit"), at("eof"), at("close"));
    assert!(exit.is_some() && eof.is_some() && close.is_some(), "{seen:?}");
    assert_eq!(seen.order.iter().filter(|o| **o == "exit").count(), 1, "{seen:?}");
    assert!(exit < eof && eof < close, "exit, EOF, close: {seen:?}");
    assert!(last_data.is_none_or(|d| Some(d) < exit), "each byte before the exit: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_end_comes_in_order_with_stdout_and_stderr_apart() {
    let seen = run(settings(), "printf out; printf err >&2; exit 3").await;
    assert_eq!(seen.replies, vec![true], "{seen:?}");
    assert_eq!((seen.out.as_slice(), seen.err.as_slice()), (&b"out"[..], &b"err"[..]), "{seen:?}");
    assert_eq!(seen.status, Some(3), "{seen:?}");
    ended_in_order(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_status_comes_back() {
    for (command, code) in [("exit 3", 3), ("true", 0), ("false", 1), ("podssh-no-such-command-here", 127)] {
        let seen = run(settings(), command).await;
        assert_eq!(seen.status, Some(code), "{command}: {seen:?}");
        ended_in_order(&seen);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_killed_by_a_signal_is_said_by_name() {
    let seen = run(settings(), "kill -TERM $$").await;
    assert_eq!((seen.signal.as_deref(), seen.status), (Some("TERM"), None), "{seen:?}");
    ended_in_order(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signal_request_reaches_the_command() {
    let handle = connect(settings()).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "sleep 25").await.unwrap();
    let started = Instant::now();
    loop {
        match tokio::time::timeout(LIMIT, channel.wait()).await.expect("a reply") {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) | None => panic!("the command did not start"),
            Some(_) => {}
        }
    }
    channel.signal(Sig::TERM).await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.signal.as_deref(), Some("TERM"), "{seen:?}");
    assert!(started.elapsed() < Duration::from_secs(20), "the signal ended it, not the sleep");
    ended_in_order(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdin_comes_back_whole() {
    let handle = connect(settings()).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();
    let sent: Vec<u8> = (0..1_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let (mut read, write) = channel.split();
    let body = sent.clone();
    let writer = tokio::spawn(async move {
        write.data(&body[..]).await.unwrap();
        write.eof().await.unwrap();
        write
    });
    let mut back = Vec::new();
    let mut status = None;
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = read.wait().await {
            match message {
                ChannelMsg::Data { data } => back.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("cat ends in time");
    let _write = writer.await.unwrap();
    assert_eq!(status, Some(0));
    assert_eq!(back.len(), sent.len());
    assert!(back == sent, "the bytes came back changed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_child_gets_no_credential_and_only_the_accepted_names() {
    let handle = connect(settings()).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.set_env(true, "LANG", "C.UTF-8").await.unwrap();
    channel.set_env(true, "LD_PRELOAD", "/planted.so").await.unwrap();
    channel.set_env(true, "TZ", "UTC").await.unwrap();
    channel.exec(true, "env").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![true, false, false, true], "LANG, LD_PRELOAD, TZ, exec: {seen:?}");
    let env = String::from_utf8_lossy(&seen.out);
    let has = |line: &str| env.lines().any(|l| l == line);
    assert!(has("LANG=C.UTF-8"), "{env}");
    assert!(has("SERVE_OWN=kept"), "serve's own environment stays: {env}");
    assert!(env.lines().any(|l| l.starts_with("SHELL=/")), "{env}");
    assert!(env.lines().any(|l| l.starts_with("USER=")), "{env}");
    assert!(!env.contains("LD_PRELOAD") && !env.contains("TZ="), "{env}");
    assert!(!env.contains("PODSSH_RELAY_TOKEN") && !env.contains("planted-token-of-serve"), "{env}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_env_lets_in_its_names_and_never_ld() {
    let accept = Settings { accept_env: vec!["*".into()], ..settings() };
    let handle = connect(accept).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.set_env(true, "TZ", "UTC").await.unwrap();
    channel.set_env(true, "LD_LIBRARY_PATH", "/planted").await.unwrap();
    channel.set_env(true, "BASH_ENV", "/planted").await.unwrap();
    channel.exec(true, "env").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![true, false, false, true], "{seen:?}");
    let env = String::from_utf8_lossy(&seen.out);
    assert!(env.lines().any(|l| l == "TZ=UTC"), "{env}");
    assert!(!env.contains("/planted"), "{env}");
}

/// Where no master opens (here one that is missing, as on a host with no
/// `/dev/ptmx`), the pty is refused and the command runs on pipes (T-110);
/// a granted pty is `serve_pty`'s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pty_request_is_refused_and_the_command_runs_without_one() {
    let no_master = Settings { ptmx: Some(vec!["/nonexistent/podssh-ptmx".into()]), ..settings() };
    let handle = connect(no_master).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.exec(true, "test -t 0 || echo no-tty").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![false, true], "the pty refused, the command run: {seen:?}");
    assert_eq!(String::from_utf8_lossy(&seen.out).trim(), "no-tty");
    assert_eq!(seen.status, Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_runs_as_a_login_shell_on_pipes() {
    let handle = connect(settings()).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    let (mut read, write) = channel.split();
    write.data(&b"echo $0; exit 4\n"[..]).await.unwrap();
    write.eof().await.unwrap();
    let mut out = Vec::new();
    let mut status = None;
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = read.wait().await {
            match message {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("the shell ends in time");
    let said = String::from_utf8_lossy(&out);
    // A login shell may print its profile's lines first.
    assert!(said.lines().any(|l| l.starts_with('-')), "argv[0] of a login shell: {said}");
    assert_eq!(status, Some(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_that_does_not_run_is_named_on_stderr_and_fails_the_request() {
    let named = Settings { shell: Some("/nonexistent/podssh-sh".into()), ..settings() };
    let handle = connect(named).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "true").await.unwrap();
    let mut err = Vec::new();
    let refused = tokio::time::timeout(LIMIT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => err.extend_from_slice(&data),
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("an answer in time");
    let err = String::from_utf8_lossy(&err);
    assert!(refused, "{err}");
    assert!(err.contains("--shell /nonexistent/podssh-sh: no such file"), "{err}");
    let no_shell = Settings { no_shell: true, ..settings() };
    let seen = run(no_shell, "true").await;
    assert!(seen.replies.first() == Some(&false), "--no-shell refuses: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_background_job_that_holds_the_pipes_does_not_hold_the_end() {
    let started = Instant::now();
    let seen = run(settings(), "sleep 20 & echo started").await;
    assert_eq!(String::from_utf8_lossy(&seen.out).trim(), "started");
    assert_eq!(seen.status, Some(0), "{seen:?}");
    assert!(started.elapsed() < Duration::from_secs(15), "the end waited for the job: {:?}", started.elapsed());
    ended_in_order(&seen);
}
