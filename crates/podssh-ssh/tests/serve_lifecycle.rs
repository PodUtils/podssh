//! The life of `podssh serve` (T-117), with russh's client over pipes in
//! memory, two connections to one server: a reload of the keys lets a new
//! key in at the next login and keeps the session that logged in before;
//! a set with no key never replaces the keys; a stop tells the client why
//! (`podssh serve is stopping`), hangs up each child's process group and
//! ends within its grace; a child that ignores the hangup is killed after
//! the grace, and at once on a second stop; a client that closes its
//! channel hangs up the child. The same against OpenSSH's client and a
//! SIGTERM: `podssh-cli`'s `tests/serve_lifecycle_openssh.rs`.

#![cfg(unix)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg};
use podssh_ssh::server::{self, stop, Authorized, Control, Keys, Settings};

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
    // Room for a batch of each end: two russh loops on a small pipe stop
    // each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let served = tokio::spawn(server::serve_under(far, key(), keys.clone(), settings(), control.clone()));
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
