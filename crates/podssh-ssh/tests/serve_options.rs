//! The options of a key line of `podssh serve` (T-114), with russh's client
//! over a pipe: a forced command runs in place of the asked one, with
//! `SSH_ORIGINAL_COMMAND`, and in place of a shell and of SFTP; a forced
//! `internal-sftp` serves SFTP alone; `no-pty` refuses a pty with its
//! reason and the command runs on pipes; `permitopen=` lets one target
//! through and refuses another with code 1 and its reason; `restrict`
//! refuses a pty and a forward; a past `expiry-time=` and a `from=` with no
//! client address refuse the login, and serve says why; a security key's
//! signature with no touch is refused unless `no-touch-required`, and one
//! with no verified user where `verify-required` (T-774). The parser's own
//! tests are the unit tests of `server::options`; the same against
//! OpenSSH's client: `podssh-cli`'s `tests/serve_options_openssh.rs`.

#![cfg(unix)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::agent::AgentIdentity;
use podssh_ssh::russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use podssh_ssh::russh::{self, client, ChannelId, ChannelMsg, ChannelOpenFailure};
use podssh_ssh::server::{self, Authorized, Say, Settings};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

type Heard = Arc<Mutex<Vec<String>>>;

/// The refusals of channels that a client heard: each code and reason.
type Refusals = Arc<Mutex<Vec<(u32, String)>>>;

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn base_env() -> Vec<(OsString, OsString)> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    // serve's own, as when serve itself runs under a forced command: never
    // a child's.
    vec![("PATH".into(), path), ("SSH_ORIGINAL_COMMAND".into(), "serve's own".into())]
}

/// Settings whose lines are kept in `heard`.
fn settings(heard: &Heard) -> Settings {
    let kept = heard.clone();
    let say = Say(Arc::new(move |line: &str| kept.lock().unwrap().push(line.to_string())));
    Settings { base_env: Some(base_env()), say: Some(say), ..Settings::default() }
}

struct Client {
    refusals: Refusals,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_failure(
        &mut self,
        _channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        _language: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refusals.lock().unwrap().push((reason.code(), description.to_string()));
        Ok(())
    }
}

/// A server whose one key line is `OPTIONS KEY`, and the client's attempt
/// to log in with that key: the handle, and whether the login passed.
async fn login(options: &str, settings: Settings) -> (client::Handle<Client>, bool) {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let line = format!("{options} {}", login.public_key().to_openssh().unwrap());
    let mut authorized = Authorized::new();
    let read = authorized.add_text(&line);
    assert_eq!((read.added, read.bad.len()), (1, 0), "{line}: {read:?}");
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let heard = Client { refusals: Arc::default() };
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, heard).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    let passed = handle.authenticate_publickey("anyone", login).await.unwrap().success();
    (handle, passed)
}

async fn logged_in(options: &str, settings: Settings) -> client::Handle<Client> {
    let (handle, passed) = login(options, settings).await;
    assert!(passed, "{options}: the key logs in");
    handle
}

/// What a channel gave until its close.
#[derive(Debug, Default)]
struct Seen {
    out: String,
    err: String,
    replies: Vec<bool>,
    status: Option<u32>,
}

async fn read_to_close(channel: &mut russh::Channel<client::Msg>) -> Seen {
    let mut seen = Seen::default();
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => seen.out.push_str(&String::from_utf8_lossy(&data)),
                ChannelMsg::ExtendedData { data, ext: 1 } => seen.err.push_str(&String::from_utf8_lossy(&data)),
                ChannelMsg::Success => seen.replies.push(true),
                ChannelMsg::Failure => seen.replies.push(false),
                ChannelMsg::ExitStatus { exit_status } => seen.status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("the channel closes in time");
    seen
}

const FORCED: &str = r#"command="echo forced; echo \"orig=${SSH_ORIGINAL_COMMAND-unset}\"""#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_command_runs_in_place_of_the_asked_one() {
    let heard = Heard::default();
    let handle = logged_in(FORCED, settings(&heard)).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo asked").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![true], "{seen:?}");
    assert_eq!(seen.out, "forced\norig=echo asked\n", "{seen:?}");
    assert_eq!(seen.status, Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_command_runs_for_a_shell_and_for_sftp() {
    let heard = Heard::default();
    let handle = logged_in(FORCED, settings(&heard)).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.out, "forced\norig=unset\n", "a shell has no original command, nor serve's own: {seen:?}");
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.out, "forced\norig=internal-sftp\n", "{seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_internal_sftp_refuses_a_command_with_its_reason() {
    let heard = Heard::default();
    let handle = logged_in(r#"command="internal-sftp""#, settings(&heard)).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "id").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![false], "{seen:?}");
    assert!(seen.err.contains("SFTP alone"), "the reason on stderr: {seen:?}");
    assert!(heard.lock().unwrap().iter().any(|l| l.contains("SFTP alone")), "and in serve's log");
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let mut channel = channel;
    let reply = tokio::time::timeout(LIMIT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return true,
                Some(ChannelMsg::Failure) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("an answer");
    assert!(reply, "SFTP is served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_pty_refuses_the_pty_with_its_reason_and_the_command_runs() {
    let heard = Heard::default();
    let handle = logged_in("no-pty", settings(&heard)).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.exec(true, "test -t 0 || echo no-tty").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![false, true], "{seen:?}");
    assert!(seen.err.contains("no-pty"), "{seen:?}");
    assert_eq!(seen.out.trim(), "no-tty");
}

/// A listener of the test that echoes one connection: its port.
async fn echo_once() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        while let Ok(n @ 1..) = tcp.read(&mut buf).await {
            if tcp.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    port
}

/// The refusal of a forward to `port`, as the client heard it.
async fn refusal(handle: &client::Handle<Client>, refusals: &Refusals, port: u16) -> (u32, String) {
    let opened = handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1).await;
    assert!(opened.is_err(), "127.0.0.1:{port} must be refused");
    let wait = async {
        loop {
            if let Some(heard) = refusals.lock().unwrap().last().cloned() {
                return heard;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(LIMIT, wait).await.expect("the client heard the refusal")
}

/// A logged-in client and the refusals of channels that it hears.
async fn forwarding(options: &str) -> (client::Handle<Client>, Refusals) {
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add_text(&format!("{options} {}", login.public_key().to_openssh().unwrap()));
    let settings = settings(&Heard::default());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let refusals = Refusals::default();
    let client = Client { refusals: refusals.clone() };
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, client).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    (handle, refusals)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permitopen_lets_its_target_through_and_refuses_another() {
    let port = echo_once().await;
    let other = echo_once().await;
    let (handle, refusals) = forwarding(&format!(r#"permitopen="127.0.0.1:{port}""#)).await;
    let opened = handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1).await;
    let channel = opened.expect("its target is let through");
    let (mut read, write) = channel.split();
    write.data(&b"ping"[..]).await.unwrap();
    let back = tokio::time::timeout(LIMIT, async {
        loop {
            if let Some(ChannelMsg::Data { data }) = read.wait().await {
                return data.to_vec();
            }
        }
    })
    .await
    .expect("the echo");
    assert_eq!(back, b"ping");
    let (code, why) = refusal(&handle, &refusals, other).await;
    assert_eq!(code, 1, "administratively prohibited: {why}");
    assert!(why.contains("permitopen") && why.contains(&format!("127.0.0.1:{other}")), "{why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restrict_refuses_a_pty_and_a_forward() {
    let port = echo_once().await;
    let (handle, refusals) = forwarding("restrict").await;
    let (code, why) = refusal(&handle, &refusals, port).await;
    assert_eq!(code, 1, "{why}");
    assert!(why.contains("no-port-forwarding"), "{why}");
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.exec(true, "true").await.unwrap();
    let seen = read_to_close(&mut channel).await;
    assert_eq!(seen.replies, vec![false, true], "{seen:?}");
    assert!(seen.err.contains("no-pty"), "{seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_past_expiry_time_refuses_the_login_and_says_why() {
    let heard = Heard::default();
    let (_handle, passed) = login(r#"expiry-time="20200101Z""#, settings(&heard)).await;
    assert!(!passed, "an expired key logs in");
    let said = heard.lock().unwrap().join("\n");
    assert!(said.contains("refused") && said.contains("expiry-time"), "{said}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_needs_an_address_that_matches() {
    let heard = Heard::default();
    let (_handle, passed) = login(r#"from="127.0.0.1""#, settings(&heard)).await;
    assert!(!passed, "a pipe has no address: no from= matches");
    assert!(heard.lock().unwrap().iter().any(|l| l.contains("no address")), "{:?}", heard.lock().unwrap());
    let peer = Some("127.0.0.1".parse().unwrap());
    let (_handle, passed) = login(r#"from="127.0.0.0/8""#, Settings { peer, ..settings(&heard) }).await;
    assert!(passed, "an address in the block");
    let (_handle, passed) = login(r#"from="10.0.0.0/8""#, Settings { peer, ..settings(&heard) }).await;
    assert!(!passed, "an address out of it");
}

/// The application of the test's security key, as `ssh-keygen -t ed25519-sk`
/// names it by default.
const APPLICATION: &str = "ssh:";
const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// The flags of a signature (OpenSSH's PROTOCOL.u2f): bit 0 the touch, bit
/// 2 the user verified.
const TOUCHED: u8 = 0x01;
const VERIFIED: u8 = 0x04;

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A security key in software whose signatures carry the flags that the
/// test chooses: it signs as a FIDO device signs, the SHA-256 of the
/// application, the flags, the counter and the SHA-256 of the message, so
/// the server's check of the signature passes whatever the flags say.
struct SoftSk {
    pair: Ed25519KeyPair,
    flags: u8,
}

impl SoftSk {
    fn new(flags: u8) -> SoftSk {
        SoftSk { pair: Ed25519KeyPair::generate().expect("an Ed25519 key"), flags }
    }

    /// The key as SSH holds it: the type, the point and the application.
    fn public(&self) -> PublicKey {
        let mut blob = Vec::new();
        put_string(&mut blob, SK_ED25519.as_bytes());
        put_string(&mut blob, self.pair.public_key().as_ref());
        put_string(&mut blob, APPLICATION.as_bytes());
        PublicKey::from_bytes(&blob).expect("an sk-ssh-ed25519 key")
    }
}

impl russh::Signer for SoftSk {
    type Error = russh::SendError;

    /// `to_sign`, then its signature as an agent gives it, as podssh's own
    /// signer of a security key answers.
    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        let counter: u32 = 7;
        let mut signed = Sha256::digest(APPLICATION.as_bytes()).to_vec();
        signed.push(self.flags);
        signed.extend_from_slice(&counter.to_be_bytes());
        signed.extend_from_slice(&Sha256::digest(&to_sign));
        let signature = self.pair.sign(&signed);
        let mut blob = Vec::new();
        put_string(&mut blob, SK_ED25519.as_bytes());
        put_string(&mut blob, signature.as_ref());
        blob.push(self.flags);
        blob.extend_from_slice(&counter.to_be_bytes());
        put_string(&mut to_sign, &blob);
        Ok(to_sign)
    }
}

/// Whether a security key whose signature carries `flags` logs in, where
/// its one line is `OPTIONS KEY`.
async fn sk_login(options: &str, flags: u8, heard: &Heard) -> bool {
    let (near, far) = tokio::io::duplex(1 << 22);
    let mut sk = SoftSk::new(flags);
    let public = sk.public();
    let line = format!("{options} {}", public.to_openssh().unwrap());
    let mut authorized = Authorized::new();
    let read = authorized.add_text(&line);
    assert_eq!((read.added, read.bad.len()), (1, 0), "{line}: {read:?}");
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings(heard))));
    let client = Client { refusals: Arc::default() };
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, client).await.unwrap();
    let call = handle.authenticate_publickey_with("anyone", public, None, &mut sk);
    let passed = tokio::time::timeout(LIMIT, call).await.expect("the login ends in time").unwrap().success();
    drop(handle);
    passed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_security_key_that_signs_with_no_touch_is_refused_and_serve_says_why() {
    let heard = Heard::default();
    assert!(sk_login("", TOUCHED, &heard).await, "a signature with the touch logs in");
    assert!(!sk_login("", 0, &heard).await, "a signature with no touch logs in");
    let said = heard.lock().unwrap().join("\n");
    assert!(said.contains("refused") && said.contains("no touch"), "{said}");
    // A line may ask for the touch by name too; that is the default.
    assert!(!sk_login("touch-required", 0, &heard).await, "touch-required takes no touch");
    // restrict leaves the touch asked for, as in sshd.
    assert!(!sk_login("restrict", 0, &heard).await, "restrict waives the touch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_touch_required_takes_a_signature_with_no_touch() {
    let heard = Heard::default();
    assert!(sk_login("no-touch-required", 0, &heard).await, "no-touch-required refuses a signature with no touch");
    assert!(sk_login("no-touch-required", TOUCHED, &heard).await, "and one with the touch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_required_refuses_a_touch_with_no_verified_user() {
    let heard = Heard::default();
    assert!(!sk_login("verify-required", TOUCHED, &heard).await, "verify-required takes a touch alone");
    let said = heard.lock().unwrap().join("\n");
    assert!(said.contains("refused") && said.contains("verify-required"), "{said}");
    assert!(sk_login("verify-required", TOUCHED | VERIFIED, &heard).await, "a touch with the user verified");
    // The two are apart: no touch with the user verified, as sshd reads them.
    assert!(!sk_login("verify-required", VERIFIED, &heard).await, "a verified user with no touch");
    assert!(sk_login("no-touch-required,verify-required", VERIFIED, &heard).await, "with no-touch-required");
}
