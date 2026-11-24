//! The life of `podssh serve` (T-117), with russh's client over pipes in
//! memory, two connections to one server: a reload of the keys lets a new
//! key in at the next login and keeps the session that logged in before;
//! a set with no key never replaces the keys; a stop tells the client why
//! (`podssh serve is stopping`), hangs up each child's process group and
//! ends within its grace; a child that ignores the hangup is killed after
//! the grace, and at once on a second stop; a client that closes its
//! channel hangs up the child. With `--revoke-ends-sessions` (T-842), a
//! reload that takes one of two keys out ends that key's session, with its
//! name to the client and its child gone, and the other key's goes on;
//! without the flag neither ends; a key's `expiry-time=` ends its session
//! at that second. A client that leaves with no DISCONNECT after its login
//! ends its connection as its own end (T-869). The same against OpenSSH's
//! client and a SIGTERM or a SIGHUP: `podssh-cli`'s
//! `tests/serve_lifecycle_openssh.rs` and `tests/serve_end_openssh.rs`.

#![cfg(unix)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg};
use podssh_ssh::server::{self, live, stop, Authorized, Control, Keys, Reloaded, Rules, Say, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn settings() -> Arc<Settings> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path)];
    Arc::new(Settings { base_env: Some(base), ..Settings::default() })
}

fn only(login: &PrivateKey) -> Authorized {
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    authorized
}

/// The client's handler: it trusts the host key, and keeps the reason of a
/// disconnect that the server sent.
#[derive(Clone, Default)]
struct Client {
    said: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                *self.said.lock().unwrap() = Some(info.message);
                Ok(())
            }
            client::DisconnectReason::Error(e) => Err(e),
        }
    }
}

/// One connection to the server of `keys` and `control`: the client's
/// handle and whether `login` logged in, and the server's task.
async fn connect(
    keys: &Keys,
    control: &Control,
    login: &PrivateKey,
    seen: Client,
) -> (client::Handle<Client>, bool, tokio::task::JoinHandle<Result<(), String>>) {
    connect_with(keys, control, login, seen, settings()).await
}

/// [`connect`] with the server's `settings`.
async fn connect_with(
    keys: &Keys,
    control: &Control,
    login: &PrivateKey,
    seen: Client,
    settings: Arc<Settings>,
) -> (client::Handle<Client>, bool, tokio::task::JoinHandle<Result<(), String>>) {
    // Room for a batch of each end: two russh loops on a small pipe stop
    // each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let served = tokio::spawn(server::serve_under(far, key(), keys.clone(), settings, control.clone()));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, seen).await.unwrap();
    let signed = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
    let ok = handle.authenticate_publickey("anyone", signed).await.unwrap().success();
    (handle, ok, served)
}

/// Run `command` on a new channel, and read the child's pid from its first
/// line of output.
async fn start(handle: &client::Handle<Client>, command: &str) -> (russh::Channel<client::Msg>, i32) {
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut out = Vec::new();
    let pid = tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                out.extend_from_slice(&data);
                if let Some(end) = out.iter().position(|b| *b == b'\n') {
                    return String::from_utf8_lossy(&out[..end]).trim().parse::<i32>().ok();
                }
            }
        }
        None
    })
    .await
    .expect("the child says its pid in time")
    .expect("a pid");
    (channel, pid)
}

/// Whether `pid` still runs: a process that ended and was reaped is gone.
fn runs(pid: i32) -> bool {
    // SAFETY: kill with 0 sends nothing; it only asks.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// How long `pid` ran on, within `limit`; None when it still runs then.
async fn gone_within(pid: i32, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if !runs(pid) {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_lets_a_new_key_in_and_keeps_the_session_before() {
    let (first, second) = (key(), key());
    let keys = Keys::new(only(&first));
    let control = Control::new();
    let (one, ok, _served) = connect(&keys, &control, &first, Client::default()).await;
    assert!(ok, "the first key logs in");
    let mut cat = one.channel_open_session().await.unwrap();
    cat.exec(true, "cat").await.unwrap();
    let (_, refused, _) = connect(&keys, &control, &second, Client::default()).await;
    assert!(!refused, "the second key is not listed yet");

    assert!(keys.replace(only(&second)), "the reload takes the second key alone");
    assert!(!keys.replace(Authorized::new()), "a set with no key never replaces the keys");
    let (_two, ok, _) = connect(&keys, &control, &second, Client::default()).await;
    assert!(ok, "after the reload the second key logs in");
    let (_, ok, _) = connect(&keys, &control, &first, Client::default()).await;
    assert!(!ok, "and the first key, out of the new set, does not");

    // The session of the first key goes on.
    cat.data(&b"still here\n"[..]).await.unwrap();
    let back = tokio::time::timeout(LIMIT, async {
        let mut back = Vec::new();
        while let Some(message) = cat.wait().await {
            if let ChannelMsg::Data { data } = message {
                back.extend_from_slice(&data);
                if back.ends_with(b"\n") {
                    break;
                }
            }
        }
        back
    })
    .await
    .expect("cat answers in time");
    assert_eq!(back, b"still here\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_says_why_and_hangs_up_each_child() {
    let login = key();
    let keys = Keys::new(only(&login));
    let control = Control::new();
    let seen = Client::default();
    let (handle, ok, served) = connect(&keys, &control, &login, seen.clone()).await;
    assert!(ok);
    let (_a, first) = start(&handle, "echo $$; exec sleep 100").await;
    let (_b, second) = start(&handle, "echo $$; exec sleep 100").await;
    assert!(runs(first) && runs(second));
    assert_eq!(control.children(), 2, "each child's group is known to the stop");

    let stopped = Instant::now();
    control.stop();
    let ended = tokio::time::timeout(stop::GRACE + Duration::from_secs(3), served).await;
    let ended = ended.expect("the server ends within its grace").expect("its task");
    assert_eq!(ended, Ok(()), "a stop is a clean end");
    for pid in [first, second] {
        let took = gone_within(pid, Duration::from_secs(5)).await;
        assert!(took.is_some(), "the child {pid} still runs after the stop");
    }
    assert!(stopped.elapsed() < stop::GRACE, "the hangup ended them before the grace: {:?}", stopped.elapsed());
    let mut said = None;
    for _ in 0..40 {
        said = seen.said.lock().unwrap().clone();
        if said.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(said.as_deref(), Some(stop::STOPPING), "the client is told why");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_child_that_ignores_the_hangup_is_killed_after_the_grace() {
    let login = key();
    let keys = Keys::new(only(&login));
    let control = Control::new();
    let (handle, _, _served) = connect(&keys, &control, &login, Client::default()).await;
    let (_channel, pid) = start(&handle, "trap '' HUP; echo $$; while :; do sleep 1; done").await;
    let stopped = Instant::now();
    control.stop();
    let took = gone_within(pid, stop::GRACE + Duration::from_secs(5)).await.expect("killed after the grace");
    let took = stopped.elapsed().max(took);
    assert!(took >= stop::GRACE - Duration::from_millis(500), "it ignored the hangup, yet ended at {took:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_stop_kills_at_once() {
    let login = key();
    let keys = Keys::new(only(&login));
    let control = Control::new();
    let (handle, _, _served) = connect(&keys, &control, &login, Client::default()).await;
    let (_channel, pid) = start(&handle, "trap '' HUP; echo $$; while :; do sleep 1; done").await;
    control.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(runs(pid), "the hangup is ignored");
    control.stop();
    let took = gone_within(pid, Duration::from_secs(2)).await;
    assert!(took.is_some(), "a second stop kills at once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_closes_its_channel_hangs_up_the_child() {
    let login = key();
    let keys = Keys::new(only(&login));
    let control = Control::new();
    let (handle, _, _served) = connect(&keys, &control, &login, Client::default()).await;
    let (channel, pid) = start(&handle, "echo $$; exec sleep 100").await;
    channel.close().await.unwrap();
    let took = gone_within(pid, Duration::from_secs(5)).await;
    assert!(took.is_some(), "the child of a closed channel still runs");
    // The slot is cleared just after the child is reaped.
    for _ in 0..20 {
        if control.children() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(control.children(), 0, "and its group is no longer counted");
}

/// The reason of the disconnect that `seen` got, within 2 s.
async fn told(seen: &Client) -> Option<String> {
    for _ in 0..40 {
        if let Some(said) = seen.said.lock().unwrap().clone() {
            return Some(said);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Kill what a test left running.
fn kill(pid: i32) {
    // SAFETY: kill has no memory effect; a pid gone gives ESRCH.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_that_takes_a_key_out_ends_its_session_when_asked_and_the_other_goes_on() {
    let (first, second) = (key(), key());
    let mut both = only(&first);
    both.add(second.public_key().key_data().clone());
    let keys = Keys::new(both);
    let control = Control::new();
    let (seen_one, seen_two) = (Client::default(), Client::default());
    let (one, ok, served_one) = connect(&keys, &control, &first, seen_one.clone()).await;
    assert!(ok, "the first key logs in");
    let (two, ok, served_two) = connect(&keys, &control, &second, seen_two.clone()).await;
    assert!(ok, "the second key logs in");
    assert_eq!(control.sessions(), 2);
    let (_a, child_one) = start(&one, "echo $$; exec sleep 100").await;
    let (_b, child_two) = start(&two, "echo $$; exec sleep 100").await;

    // Without the flag: the first key is out of the set, and both go on (T-117).
    assert_eq!(live::reload(&keys, &control, only(&second), false), Reloaded::Taken(Vec::new()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(runs(child_one) && runs(child_two), "without the flag no session ends");
    assert!(seen_one.said.lock().unwrap().is_none(), "nor is a client told anything");
    // A set with no key is refused, and ends nothing even with the flag.
    assert_eq!(live::reload(&keys, &control, Authorized::new(), true), Reloaded::Refused);
    assert!(runs(child_one), "a refused set ends nothing");

    // With the flag: the first key's session ends, named; the second's lives.
    let ended = match live::reload(&keys, &control, only(&second), true) {
        Reloaded::Taken(ended) => ended,
        Reloaded::Refused => panic!("a set with a key is taken"),
    };
    let who = podssh_ssh::known_hosts::fingerprint(first.public_key());
    assert_eq!(ended.iter().map(|e| e.who.clone()).collect::<Vec<_>>(), vec![who.clone()], "{ended:?}");
    assert!(ended[0].to_string().contains(&who), "the line names the key: {}", ended[0]);
    let ended_in = tokio::time::timeout(stop::GRACE + Duration::from_secs(3), served_one).await;
    assert_eq!(ended_in.expect("the connection ends").expect("its task"), Ok(()), "a clean end");
    assert!(gone_within(child_one, Duration::from_secs(5)).await.is_some(), "the removed key's child is gone");
    let said = told(&seen_one).await;
    assert!(said.as_deref().is_some_and(|s| s.contains(&who)), "the client hears which key: {said:?}");
    assert!(runs(child_two), "the other key's child runs on");
    assert!(!served_two.is_finished(), "and its connection lives");
    let (_c, again) = start(&two, "echo $$; exec sleep 100").await;
    assert!(runs(again), "the other key still runs a command");
    for _ in 0..40 {
        if control.sessions() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(control.sessions(), 1, "the ended connection left the table");
    for pid in [child_two, again] {
        kill(pid);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_that_expires_ends_its_session_at_its_time_when_asked() {
    let login = key();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut authorized = Authorized::new();
    let rules = Rules { expiry: Some(now + 2), ..Rules::default() };
    authorized.add_ruled(login.public_key().key_data().clone(), rules, "a test".into());
    let keys = Keys::new(authorized);
    let control = Control::new();
    let heard = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = heard.clone();
    let say = Say(Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_string())));
    let settings = Arc::new(Settings { revoke_ends_sessions: true, say: Some(say), ..(*settings()).clone() });
    let seen = Client::default();
    let (handle, ok, served) = connect_with(&keys, &control, &login, seen.clone(), settings).await;
    assert!(ok, "the key logs in before its time");
    let (_channel, child) = start(&handle, "echo $$; exec sleep 100").await;
    let ended = tokio::time::timeout(Duration::from_secs(4) + stop::GRACE, served).await;
    assert_eq!(ended.expect("the connection ends at the key's time").expect("its task"), Ok(()));
    assert!(gone_within(child, Duration::from_secs(5)).await.is_some(), "its child is gone");
    let said = told(&seen).await;
    assert!(said.as_deref().is_some_and(|s| s.contains("expired")), "the client hears why: {said:?}");
    let heard = heard.lock().unwrap().join("\n");
    let who = podssh_ssh::known_hosts::fingerprint(login.public_key());
    assert!(heard.contains(&who) && heard.contains("expiry-time"), "one line names the key: {heard}");
}

/// A client that leaves with no DISCONNECT (OpenSSH after a refused
/// forward, or a client whose link dropped) ends its connection: after its
/// login that is its own end, `Ok` with no failure line; before its login,
/// one true line that says so, never "the SSH connection failed" (T-869).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_leaves_with_no_disconnect_ends_its_connection() {
    for logs_in in [true, false] {
        let login = key();
        let (keys, control) = (Keys::new(only(&login)), Control::new());
        // A pump between the two ends: its abort drops both of its sides,
        // as a client gone at once.
        let (near, client_side) = tokio::io::duplex(1 << 22);
        let (server_side, far) = tokio::io::duplex(1 << 22);
        let served = tokio::spawn(server::serve_under(far, key(), keys, settings(), control));
        let pump = tokio::spawn(async move {
            let (mut a, mut b) = (client_side, server_side);
            let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        });
        let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Client::default())
            .await
            .expect("the key exchange");
        if logs_in {
            let signed = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
            assert!(handle.authenticate_publickey("anyone", signed).await.unwrap().success());
        }
        pump.abort();
        let ended = tokio::time::timeout(LIMIT, served).await.expect("serve ends in time").expect("joined");
        if logs_in {
            assert_eq!(ended, Ok(()), "the client's own end");
        } else {
            let why = ended.expect_err("no login");
            assert!(why.starts_with("the client closed the connection before it logged in"), "{why}");
        }
        drop(handle);
    }
}
