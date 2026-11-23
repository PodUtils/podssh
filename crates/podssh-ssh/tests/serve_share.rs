//! A live shell shared by name (T-837), with russh's client over pipes in
//! memory, several connections to one server with `--share`: the owner's
//! login shell on a pty is told two names on its stderr; a login under the
//! `ro-` name, with a key that the server does not know, reads the owner's
//! output, and none of its bytes (a paste before its shell request, keys
//! typed after, extended data) reaches the pty, while its window change
//! does; two logins under the `rw-` name type, and the lease keeps the
//! line of one from the line of the other; a deleted name refuses a new
//! login and leaves the seat that it opened; a name runs nothing else; the
//! names die with the shell, whose seats then exit 0; without `--share`, a
//! name is a wrong key. Where no pty opens here, each test says that it
//! did not run.

#![cfg(unix)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg, ChannelWriteHalf};
use podssh_ssh::server::{self, pty, share, Authorized, Control, Keys, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// Whether a pty opens here; else the line that says the test did not run.
fn have_pty() -> bool {
    match pty::open() {
        Ok(_) => true,
        Err(why) => {
            eprintln!("did not run: no pty here: {why}");
            false
        }
    }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One server: its keys, its control and its settings.
struct Server {
    keys: Keys,
    control: Control,
    settings: Arc<Settings>,
    owner: PrivateKey,
}

impl Server {
    fn new(share: bool) -> Server {
        let owner = key();
        let mut authorized = Authorized::new();
        authorized.add(owner.public_key().key_data().clone());
        let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path)];
        let settings = Arc::new(Settings { base_env: Some(base), share, ..Settings::default() });
        Server { keys: Keys::new(authorized), control: Control::new(), settings, owner }
    }

    /// A connection that logs in as `user` with `login`; None when refused.
    async fn login(&self, user: &str, login: &PrivateKey) -> Option<client::Handle<Trusting>> {
        // Room for a batch of each end: two russh loops on a small pipe stop
        // each other (T-772).
        let (near, far) = tokio::io::duplex(1 << 22);
        let (keys, control) = (self.keys.clone(), self.control.clone());
        tokio::spawn(server::serve_under(far, key(), keys, self.settings.clone(), control));
        let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
        let signed = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
        let ok = handle.authenticate_publickey(user, signed).await.unwrap().success();
        ok.then_some(handle)
    }
}

/// What a channel gave, read on a task of its own.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    err: Vec<u8>,
    replies: Vec<bool>,
    status: Option<u32>,
    closed: bool,
}

impl Seen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    fn lines(&self) -> Vec<String> {
        self.text().lines().map(|l| l.trim_end_matches('\r').to_string()).collect()
    }
}

/// A channel's writing half, and what its reader saw.
struct Seat {
    write: ChannelWriteHalf<client::Msg>,
    seen: Arc<Mutex<Seen>>,
    _kept: client::Handle<Trusting>,
}

impl Seat {
    /// A session channel of `handle`, read from now on.
    async fn open(handle: client::Handle<Trusting>) -> Seat {
        let (mut read, write) = handle.channel_open_session().await.unwrap().split();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let into = seen.clone();
        tokio::spawn(async move {
            while let Some(message) = read.wait().await {
                let mut seen = into.lock().unwrap();
                match message {
                    ChannelMsg::Data { data } => seen.out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, .. } => seen.err.extend_from_slice(&data),
                    ChannelMsg::Success => seen.replies.push(true),
                    ChannelMsg::Failure => seen.replies.push(false),
                    ChannelMsg::ExitStatus { exit_status } => seen.status = Some(exit_status),
                    ChannelMsg::Close => {
                        seen.closed = true;
                        break;
                    }
                    _ => {}
                }
            }
        });
        Seat { write, seen, _kept: handle }
    }

    /// A pty of `cols` by `rows`, then the shell; both replies.
    async fn shell(handle: client::Handle<Trusting>, cols: u32, rows: u32) -> Seat {
        let seat = Seat::open(handle).await;
        seat.write.request_pty(true, "vt100", cols, rows, 0, 0, &[]).await.unwrap();
        seat.write.request_shell(true).await.unwrap();
        seat.until("both replies", |seen| seen.replies.len() >= 2).await;
        seat
    }

    async fn send(&self, bytes: &[u8]) {
        self.write.data(bytes).await.unwrap();
    }

    /// Wait until `what` holds of what was seen.
    async fn until(&self, name: &str, what: impl Fn(&Seen) -> bool) {
        let waited = tokio::time::timeout(LIMIT, async {
            while !what(&self.seen.lock().unwrap()) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "no {name} in time: {:?}", self.seen.lock().unwrap());
    }

    /// Wait until the output holds `needle`.
    async fn reads(&self, needle: &str) {
        self.until(needle, |seen| seen.text().contains(needle)).await;
    }
}

/// The owner's shell on a pty of 80x24, and its two names from its stderr.
async fn owner(server: &Server) -> (Seat, String, String) {
    let handle = server.login("owner", &server.owner).await.expect("the owner's key logs in");
    let seat = Seat::shell(handle, 80, 24).await;
    assert_eq!(seat.seen.lock().unwrap().replies, vec![true, true], "the pty, then the shell");
    seat.until("the names", |seen| String::from_utf8_lossy(&seen.err).contains("watches it")).await;
    let err = String::from_utf8_lossy(&seat.seen.lock().unwrap().err).into_owned();
    let name = |prefix: &str| {
        let word = err.split_whitespace().find(|w| w.starts_with(prefix)).unwrap_or_else(|| panic!("{prefix}: {err}"));
        assert_eq!(word.len(), 3 + 32, "128 bits in hex: {word}");
        word.to_string()
    };
    (seat, name("rw-"), name("ro-"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watcher_reads_and_none_of_its_bytes_reach_the_pty() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let (owner, _, read) = owner(&server).await;
    let handle = server.login(&read, &key()).await.expect("the name lets an unknown key in");
    let viewer = Seat::open(handle).await;
    // The second path to the pty: bytes before the attach, kept for the
    // program that a channel runs.
    viewer.send(b"EARLY_PASTE\r").await;
    viewer.write.request_pty(true, "xterm", 100, 30, 0, 0, &[]).await.unwrap();
    viewer.write.request_shell(true).await.unwrap();
    viewer.until("both replies", |seen| seen.replies.len() >= 2).await;
    assert_eq!(viewer.seen.lock().unwrap().replies, vec![true, true], "a name's pty and shell");
    viewer.send(b"VIEWER_KEYS\r").await;
    viewer.write.extended_data(1, &b"VIEWER_EXT\r"[..]).await.unwrap();
    viewer.write.window_change(40, 10, 0, 0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    owner.send(b"stty size; echo OWNER_$((1+1))\r").await;
    owner.reads("OWNER_2").await;
    viewer.reads("OWNER_2").await;
    let (seen, watched) = (owner.seen.lock().unwrap().text(), viewer.seen.lock().unwrap().text());
    assert!(seen.lines().any(|l| l.trim_end_matches('\r') == "10 40"), "the watcher's size counts: {seen}");
    for word in ["EARLY_PASTE", "VIEWER_KEYS", "VIEWER_EXT"] {
        assert!(!seen.contains(word) && !watched.contains(word), "{word} reached the pty: {seen}");
    }

    // A name runs nothing else.
    let other = Seat::open(server.login(&read, &key()).await.expect("again")).await;
    other.write.exec(true, "echo RAN").await.unwrap();
    other.until("the refusal", |seen| !seen.replies.is_empty()).await;
    assert_eq!(other.seen.lock().unwrap().replies, vec![false]);
    assert!(String::from_utf8_lossy(&other.seen.lock().unwrap().err).contains("shared shell"));

    // A deleted name lets no one new in, and the seat that it opened stays.
    assert!(server.control.unshare(&read));
    assert!(server.login(&read, &key()).await.is_none(), "a deleted name is a wrong key");
    owner.send(b"echo AFTER_$((2+3))\r").await;
    viewer.reads("AFTER_5").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writers_take_turns_and_no_line_interleaves() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let (owner, write, _) = owner(&server).await;
    // The shell answers, then becomes cat; the owner's lease passes.
    owner.send(b"echo GO_$((1+2))\r").await;
    owner.reads("GO_3").await;
    owner.send(b"exec cat\r").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let first = Seat::shell(server.login(&write, &key()).await.expect("a writer"), 80, 24).await;
    let second = Seat::shell(server.login(&write, &key()).await.expect("a second writer"), 80, 24).await;
    first.send(b"aaa").await;
    owner.reads("aaa").await;
    // Sent while the first writer holds the lease: held, not mixed in.
    second.send(b"bbbbbb\r").await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    first.send(b"aaa\r").await;
    owner.until("cat's copy of each line", |seen| seen.text().matches("bbbbbb").count() >= 2).await;
    let lines = owner.seen.lock().unwrap().lines();
    assert!(lines.iter().any(|l| l == "aaaaaa"), "the first writer's line is whole: {lines:?}");
    assert!(lines.iter().any(|l| l == "bbbbbb"), "the second writer's line is whole: {lines:?}");
    let typed = lines.iter().filter(|l| l.contains("aaa") || l.contains("bbb"));
    assert!(typed.clone().all(|l| l == "aaaaaa" || l == "bbbbbb"), "interleaved: {lines:?}");
    assert_eq!(typed.count(), 4, "the echo and cat's copy of each line: {lines:?}");
    second.reads("aaaaaa").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_names_die_with_the_shell_and_each_seat_exits_0() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let (owner, write, read) = owner(&server).await;
    assert_eq!(server.control.shared(), 2);
    let viewer = Seat::shell(server.login(&read, &key()).await.expect("a watcher"), 80, 24).await;
    owner.send(b"exit 3\r").await;
    owner.until("the owner's end", |seen| seen.closed).await;
    viewer.until("the seat's end", |seen| seen.closed).await;
    assert_eq!(viewer.seen.lock().unwrap().status, Some(0));
    assert_eq!(server.control.shared(), 0);
    for name in [&write, &read] {
        assert!(server.login(name, &key()).await.is_none(), "{name} died with its shell");
    }
    assert!(server.control.reshare(&read).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_share_a_name_is_a_wrong_key() {
    if !have_pty() {
        return;
    }
    let server = Server::new(false);
    let handle = server.login("owner", &server.owner).await.expect("the owner's key logs in");
    let seat = Seat::shell(handle, 80, 24).await;
    seat.send(b"echo READY_$((3+4))\r").await;
    seat.reads("READY_7").await;
    assert!(seat.seen.lock().unwrap().err.is_empty(), "no names told");
    assert_eq!(server.control.shared(), 0);
    assert!(server.login("rw-00000000000000000000000000000000", &key()).await.is_none());
    let lease = share::LEASE_IDLE;
    assert!(lease >= Duration::from_millis(150) && lease <= Duration::from_millis(250), "{lease:?}");
}
