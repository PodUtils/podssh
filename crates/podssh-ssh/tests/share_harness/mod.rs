//! The harness of `tests/serve_share.rs` (T-837, T-860, T-861): servers
//! with `--share` over pipes in memory, on each tty that the host gives,
//! russh's client at each seat, what each channel gave, and the owner's
//! word to its shell by `share@podssh`.

#![allow(dead_code)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg, ChannelWriteHalf};
use podssh_ssh::server::{self, pty, Authorized, Control, Keys, PtyMode, Settings};

/// A bound on each wait.
pub const LIMIT: Duration = Duration::from_secs(30);

pub fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// Whether a pty opens here; else the line that says the test did not run.
pub fn have_pty() -> bool {
    match pty::open() {
        Ok(_) => true,
        Err(why) => {
            eprintln!("did not run: no pty here: {why}");
            false
        }
    }
}

/// The tty that a shared shell runs on (T-861): a pty of the kernel, or
/// serve's own, as the line discipline on pipes or answered by seccomp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tty {
    Kernel,
    Line,
    Notify,
}

impl Tty {
    /// Each tty that this host gives, the kernel's first; a line for each
    /// that it does not give, whose cases then did not run.
    pub fn here() -> Vec<Tty> {
        let mut ttys = Vec::new();
        if have_pty() {
            ttys.push(Tty::Kernel);
        }
        ttys.push(Tty::Line);
        match notify_here() {
            Ok(()) => ttys.push(Tty::Notify),
            Err(why) => eprintln!("did not run on --pty notify: {why}"),
        }
        ttys
    }

    /// The `--pty` mode that gives this tty.
    pub fn mode(self) -> PtyMode {
        match self {
            Tty::Kernel => PtyMode::No,
            Tty::Line => PtyMode::Line,
            Tty::Notify => PtyMode::Notify,
        }
    }

    /// Whether the shell sees a tty that it can ask its size of.
    pub fn sized(self) -> bool {
        self != Tty::Line
    }
}

/// Whether serve answers a child's tty calls here (T-776, T-777).
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn notify_here() -> Result<(), String> {
    server::notify::probe().or_else(|by_notification| {
        server::notify::probe_trace().map_err(|by_trace| format!("{by_notification}; {by_trace}"))
    })
}

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn notify_here() -> Result<(), String> {
    Err("not on this system".into())
}

pub struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One server: its keys, its control and its settings.
pub struct Server {
    pub keys: Keys,
    pub control: Control,
    pub settings: Arc<Settings>,
    pub owner: PrivateKey,
}

impl Server {
    pub fn new(share: bool) -> Server {
        Server::with(share, PtyMode::Auto)
    }

    /// A server with `--share` whose shells run on `tty`.
    pub fn on(tty: Tty) -> Server {
        Server::with(true, tty.mode())
    }

    fn with(share: bool, pty: PtyMode) -> Server {
        let owner = key();
        let mut authorized = Authorized::new();
        authorized.add(owner.public_key().key_data().clone());
        let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path)];
        let settings = Arc::new(Settings { base_env: Some(base), share, pty, ..Settings::default() });
        Server { keys: Keys::new(authorized), control: Control::new(), settings, owner }
    }

    /// A connection that logs in as `user` with `login`; None when refused.
    pub async fn login(&self, user: &str, login: &PrivateKey) -> Option<client::Handle<Trusting>> {
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
pub struct Seen {
    pub out: Vec<u8>,
    pub err: Vec<u8>,
    /// The frames of the far end's screen, where the channel asked (T-303).
    pub frames: Vec<u8>,
    pub replies: Vec<bool>,
    pub status: Option<u32>,
    pub closed: bool,
}

impl Seen {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    pub fn lines(&self) -> Vec<String> {
        self.text().lines().map(|l| l.trim_end_matches('\r').to_string()).collect()
    }
}

/// A channel's writing half, and what its reader saw.
pub struct Seat {
    pub write: ChannelWriteHalf<client::Msg>,
    pub seen: Arc<Mutex<Seen>>,
    /// The connection, for a second channel of it (T-860).
    pub kept: client::Handle<Trusting>,
}

impl Seat {
    /// A session channel of `handle`, read from now on.
    pub async fn open(handle: client::Handle<Trusting>) -> Seat {
        let (mut read, write) = handle.channel_open_session().await.unwrap().split();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let into = seen.clone();
        tokio::spawn(async move {
            while let Some(message) = read.wait().await {
                let mut seen = into.lock().unwrap();
                match message {
                    ChannelMsg::Data { data } => seen.out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext } if ext == podssh_ssh::frames::EXT => {
                        seen.frames.extend_from_slice(&data)
                    }
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
        Seat { write, seen, kept: handle }
    }

    /// A pty of `cols` by `rows`, then the shell; both replies.
    pub async fn shell(handle: client::Handle<Trusting>, cols: u32, rows: u32) -> Seat {
        let seat = Seat::open(handle).await;
        seat.write.request_pty(true, "vt100", cols, rows, 0, 0, &[]).await.unwrap();
        seat.write.request_shell(true).await.unwrap();
        seat.until("both replies", |seen| seen.replies.len() >= 2).await;
        seat
    }

    pub async fn send(&self, bytes: &[u8]) {
        self.write.data(bytes).await.unwrap();
    }

    /// Wait until `what` holds of what was seen.
    pub async fn until(&self, name: &str, what: impl Fn(&Seen) -> bool) {
        let waited = tokio::time::timeout(LIMIT, async {
            while !what(&self.seen.lock().unwrap()) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "no {name} in time: {:?}", self.seen.lock().unwrap());
    }

    /// Wait until the output holds `needle`.
    pub async fn reads(&self, needle: &str) {
        self.until(needle, |seen| seen.text().contains(needle)).await;
    }
}

/// The owner's shell on a pty of 80x24, and its two names from its stderr.
pub async fn owner(server: &Server) -> (Seat, String, String) {
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

/// The owner's line `line` on a new channel of `handle`, by the subsystem
/// `share@podssh` (T-860): what the channel gave, to its close.
pub async fn ask(handle: &client::Handle<Trusting>, line: &str) -> Seen {
    let channel = handle.channel_open_session().await.expect("a second channel");
    let (mut read, write) = channel.split();
    write.request_subsystem(true, "share@podssh").await.unwrap();
    write.data(line.as_bytes()).await.unwrap();
    write.eof().await.unwrap();
    let mut seen = Seen::default();
    let read_all = async {
        while let Some(message) = read.wait().await {
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
    };
    assert!(tokio::time::timeout(LIMIT, read_all).await.is_ok(), "no answer to {line:?} in time");
    seen
}
