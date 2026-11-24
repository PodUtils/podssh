//! The one-time code of `podssh serve --totp` (T-115), with russh's client
//! over a pipe: a listed key gets a partial success with keyboard-interactive
//! next; one prompt with no echo; the code logs in; the same code on a
//! second connection is a replay and refused; a wrong code is refused; a
//! keyboard-interactive with no key first goes back to the keys. RFC 6238's
//! vectors and the window are the unit tests of `server::totp`. The same
//! through OpenSSH's client, with the code from `oathtool`:
//! `podssh-cli`'s `tests/serve_totp_openssh.rs`.

#![cfg(unix)]

mod cleanup;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::client::{self, KeyboardInteractiveAuthResponse as Answer};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, MethodKind};
use podssh_ssh::server::totp::{code, Totp};
use podssh_ssh::server::{self, Authorized, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-totp-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A new secret in `dir`, the server's settings with it, and its bytes for
/// the test's own codes.
fn secret(dir: &Path) -> (Settings, Vec<u8>) {
    let path = dir.join("totp");
    Totp::create_new(&path).unwrap();
    let bytes = code::decode_base32(&std::fs::read_to_string(&path).unwrap()).unwrap().to_vec();
    let settings = Settings { totp: Some(Arc::new(Totp::open(&path).unwrap())), ..Settings::default() };
    (settings, bytes)
}

/// The code of now.
fn now_code(secret: &[u8]) -> String {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    code::code_of(secret, code::step_of(unix)).unwrap().to_string()
}

/// A code that no step around now has.
fn wrong_code(secret: &[u8]) -> String {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let near: Vec<String> =
        (0..=4).map(|i| code::code_of(secret, code::step_of(unix) + i - 2).unwrap().to_string()).collect();
    (0..1_000_000u32).map(|n| format!("{n:06}")).find(|c| !near.contains(c)).unwrap()
}

/// A connection to a new server for `login`, with the key's answer.
async fn connect(settings: &Settings, login: &PrivateKey) -> (client::Handle<Trusting>, russh::client::AuthResult) {
    let (near, far) = tokio::io::duplex(1 << 16);
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings.clone())));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let signed = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
    let answer = handle.authenticate_publickey("tester", signed).await.unwrap();
    (handle, answer)
}

/// The prompt, then `code`: the server's last answer.
async fn give(handle: &mut client::Handle<Trusting>, code: &str) -> Answer {
    let asked = handle.authenticate_keyboard_interactive_start("tester", None).await.unwrap();
    let Answer::InfoRequest { prompts, .. } = asked else { panic!("no prompt: {asked:?}") };
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert_eq!((prompts[0].prompt.as_str(), prompts[0].echo), ("One-time code: ", false));
    tokio::time::timeout(LIMIT, handle.authenticate_keyboard_interactive_respond(vec![code.to_string()]))
        .await
        .expect("an answer in time")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_then_its_code_logs_in_once() {
    let dir = scratch("once");
    let (settings, secret) = secret(&dir);
    let login = key();
    let (mut handle, answer) = connect(&settings, &login).await;
    let russh::client::AuthResult::Failure { remaining_methods, partial_success } = answer else {
        panic!("the key alone logged in")
    };
    assert!(partial_success, "the key passed");
    assert!(remaining_methods.contains(&MethodKind::KeyboardInteractive), "{remaining_methods:?}");
    let code = now_code(&secret);
    assert!(matches!(give(&mut handle, &code).await, Answer::Success), "the code logs in");
    // The same code again, on a second connection: a replay.
    let (mut again, _) = connect(&settings, &login).await;
    let refused = give(&mut again, &code).await;
    assert!(matches!(refused, Answer::Failure { .. }), "a replay: {refused:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_code_is_refused_and_no_key_gets_no_prompt() {
    let dir = scratch("wrong");
    let (settings, secret) = secret(&dir);
    let login = key();
    let (mut handle, _) = connect(&settings, &login).await;
    let refused = give(&mut handle, &wrong_code(&secret)).await;
    assert!(matches!(refused, Answer::Failure { partial_success: true, .. }), "a wrong code: {refused:?}");
    // With no key first, keyboard-interactive goes back to the keys.
    let (near, far) = tokio::io::duplex(1 << 16);
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings.clone())));
    let mut bare = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let answer = bare.authenticate_keyboard_interactive_start("tester", None).await.unwrap();
    let Answer::Failure { remaining_methods, partial_success } = answer else { panic!("a prompt: {answer:?}") };
    assert!(!partial_success && remaining_methods.contains(&MethodKind::PublicKey), "{remaining_methods:?}");
}
