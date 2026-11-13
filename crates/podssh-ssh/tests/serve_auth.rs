//! The server core of `podssh serve` (T-107): the lines of `authorized_keys`
//! (a key, a comment, options, a bad line; the options' effects are
//! `tests/serve_options.rs`, T-114), the host key made once in its
//! state file (two starts at once keep one key, mode 0600), and russh's
//! client against the server over a pipe: the listed key logs in, another
//! key is refused, and a subsystem other than SFTP is refused with an answer
//! instead of a wait (exec runs since T-108: `tests/serve_exec.rs`;
//! direct-tcpip since T-109: `tests/serve_forward.rs`; SFTP since T-112:
//! `tests/serve_sftp.rs`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg};
use podssh_ssh::server::{self, host_key, Authorized, Line, StateFiles};

/// A bound on each wait of the handshake tests.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn line_of(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-auth-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn each_kind_of_line_is_read_as_sshd_reads_it() {
    let (a, b) = (key(), key());
    let text = format!(
        "# a comment\n\n{}\n  {} with a comment\ncommand=\"echo hi there\",no-pty {}\n{}",
        line_of(&a),
        line_of(&a),
        line_of(&b),
        "ssh-ed25519 notbase64\nnonsense\n"
    );
    let mut authorized = Authorized::new();
    let read = authorized.add_text(&text);
    // The same key twice is one key; the line with options is used with
    // its rules since T-114 (`server::options`'s tests read each option).
    assert_eq!(read.added, 2, "{read:?}");
    assert_eq!(read.limited, 1, "{read:?}");
    assert_eq!(read.bad.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![6, 7], "{read:?}");
    assert!(authorized.allows(a.public_key()));
    assert!(authorized.allows(b.public_key()), "a key after options that serve honours");
    assert_eq!(server::parse_line("   "), Line::Nothing);
    assert_eq!(server::parse_line("restrict"), Line::Bad("no public key".into()));
}

#[test]
fn no_key_allows_nobody() {
    let authorized = Authorized::new();
    assert!(authorized.is_empty());
    assert!(!authorized.allows(key().public_key()));
}

/// The cache's way, in small: a whole file through a hard link, never over
/// one that is there.
fn create(path: &Path, body: &[u8]) -> std::io::Result<bool> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("tmp{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(body)?;
    file.sync_all()?;
    drop(file);
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

const FILES: StateFiles = StateFiles { read, create, dir };

#[test]
fn two_starts_at_once_keep_one_host_key() {
    let dir = scratch("race");
    let path = dir.join(host_key::FILE);
    let gate = Arc::new(Barrier::new(8));
    let starts: Vec<_> = (0..8)
        .map(|_| {
            let (gate, path) = (gate.clone(), path.clone());
            std::thread::spawn(move || {
                gate.wait();
                let found = host_key::at(&path, &FILES).unwrap();
                (found.key.public_key().to_openssh().unwrap(), found.made)
            })
        })
        .collect();
    let seen: Vec<(String, bool)> = starts.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(seen.iter().all(|(k, _)| *k == seen[0].0), "the starts saw different keys: {seen:?}");
    assert_eq!(seen.iter().filter(|(_, made)| *made).count(), 1, "one start makes the key: {seen:?}");
    // A later start reads the same key, and makes none.
    let again = host_key::in_first(std::slice::from_ref(&dir), std::slice::from_ref(&dir), &FILES).unwrap();
    assert!(!again.made);
    assert_eq!(again.key.public_key().to_openssh().unwrap(), seen[0].0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the host key's mode");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_host_key_with_a_passphrase_is_refused() {
    let locked = keygen::protect(key(), "secret").unwrap();
    let text = locked.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
    let why = host_key::parse(&text).expect_err("refused");
    assert!(why.contains("passphrase"), "{why}");
    assert!(host_key::parse("not a key").is_err());
}

#[test]
fn no_directory_names_the_flag() {
    let why = host_key::in_first(&[], &[], &FILES).err().expect("refused");
    assert!(why.contains("--host-key"), "{why}");
}

/// A client that takes any host key: the test checks the server, not the
/// client's trust.
struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A connection to a new server that lists `listed`, logged in with
/// `login`: whether the login worked, and its handle.
async fn connect(listed: &PrivateKey, login: &PrivateKey) -> (bool, client::Handle<Trusting>) {
    let (near, far) = tokio::io::duplex(1 << 16);
    let mut authorized = Authorized::new();
    authorized.add(listed.public_key().key_data().clone());
    tokio::spawn(server::serve(far, key(), Arc::new(authorized)));
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect_stream(config, near, Trusting).await.expect("the handshake");
    let login = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
    let result = handle.authenticate_publickey("anyone", login).await.expect("an answer");
    (result.success(), handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listed_key_logs_in_and_another_is_refused() {
    let (listed, other) = (key(), key());
    let (ok, _handle) = tokio::time::timeout(LIMIT, connect(&listed, &listed)).await.expect("in time");
    assert!(ok, "the listed key must log in");
    let (ok, _handle) = tokio::time::timeout(LIMIT, connect(&listed, &other)).await.expect("in time");
    assert!(!ok, "a key that is not listed must be refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subsystem_is_refused_with_an_answer() {
    let listed = key();
    let (ok, handle) = tokio::time::timeout(LIMIT, connect(&listed, &listed)).await.expect("in time");
    assert!(ok);
    let mut channel = handle.channel_open_session().await.expect("a session channel opens");
    channel.request_subsystem(true, "podssh-no-such-subsystem").await.expect("sent");
    let answer = tokio::time::timeout(LIMIT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("an answer, not a wait");
    assert!(answer, "a subsystem other than sftp must be refused");
}
