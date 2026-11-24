//! The message of the day of `podssh serve` (T-119): the bytes that reach
//! the terminal (control characters dropped, CR LF, the cap of 64 KiB), the
//! file that is not a regular file, `~/.hushlogin`; then, with russh's
//! client over a pipe, a login shell on the line discipline shows it before
//! the first prompt, a command on the same tty shows none, a home with
//! `.hushlogin` shows none, and a login shell on a pty shows it before any
//! byte of the shell where a pty opens here.

#![cfg(unix)]

mod cleanup;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::PrivateKeyWithHashAlg;
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::motd::{self, Motd, LIMIT};
use podssh_ssh::server::{self, pty, Authorized, PtyMode, Settings};

/// A bound on each wait of a test.
const WAIT: Duration = Duration::from_secs(30);

/// A directory of this test, removed when it ends.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-motd-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir.canonicalize().unwrap()
}

/// One rule for each input: what the terminal gets.
#[test]
fn the_terminal_gets_clean_text_in_cr_lf() {
    #[rustfmt::skip]
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("plain lines", b"one\ntwo\n", b"one\r\ntwo\r\n"),
        ("a last newline is added", b"no end", b"no end\r\n"),
        ("CR LF and a lone CR are one newline", b"a\r\nb\rc\n", b"a\r\nb\r\nc\r\n"),
        ("a tab stays", b"col\tumn\n", b"col\tumn\r\n"),
        ("an escape sequence loses its ESC", b"\x1b]0;title\x07red\x1b[31m\n", b"]0;titlered[31m\r\n"),
        ("a C1 control and a bidi override go", "a\u{9b}b\u{202e}c\n".as_bytes(), b"abc\r\n"),
        ("a byte that is not UTF-8 is U+FFFD", b"x\xffy\n", "x\u{fffd}y\r\n".as_bytes()),
        ("nothing to show is nothing", b"\n\t \n", b""),
        ("an empty file is nothing", b"", b""),
    ];
    for (what, input, want) in cases {
        assert_eq!(motd::for_screen(input), *want, "{what}");
    }
    // A character that the cap cut in two is dropped, not shown as U+FFFD.
    let mut cut = vec![b'a'; LIMIT - 1];
    cut.push(0xc3);
    let shown = motd::for_screen(&cut);
    assert!(!String::from_utf8_lossy(&shown).contains('\u{fffd}'), "no U+FFFD for a cut character");
}

#[test]
fn a_long_file_is_cut_at_the_limit_and_said() {
    let dir = scratch("cap");
    let path = dir.join("motd");
    std::fs::write(&path, vec![b'x'; LIMIT + 100]).unwrap();
    let read = motd::read(&path).unwrap().expect("a file");
    assert_eq!((read.bytes.len(), read.cut), (LIMIT, true));
    let shown = motd::shown(&Motd::named(&path), None);
    assert!(shown.said.as_deref().is_some_and(|s| s.contains("longer than 64 KiB")), "{:?}", shown.said);
    std::fs::write(&path, vec![b'x'; LIMIT]).unwrap();
    let read = motd::read(&path).unwrap().expect("a file");
    assert_eq!((read.bytes.len(), read.cut), (LIMIT, false), "exactly the limit is whole");
}

/// A FIFO, a directory and no file: each refused or missed before a byte
/// is read, with no wait; the default file is missed in silence.
#[test]
fn a_file_that_is_not_regular_is_refused_at_once() {
    let dir = scratch("kinds");
    let fifo = dir.join("fifo");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid C string; mkfifo keeps nothing.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0, "mkfifo");
    let started = std::time::Instant::now();
    let why = motd::read(&fifo).expect_err("a FIFO");
    assert!(why.ends_with("not a regular file") && started.elapsed() < Duration::from_secs(2), "{why}");
    assert!(motd::read(&dir).expect_err("a directory").ends_with("not a regular file"));
    let missing = dir.join("missing");
    assert_eq!(motd::read(&missing), Ok(None));
    assert_eq!(motd::shown(&Motd { path: missing.clone(), named: false }, None), motd::Shown::default());
    let named = motd::shown(&Motd::named(&missing), None);
    assert!(named.screen.is_none() && named.said.is_some_and(|s| s.contains("no such file")));
    assert!(motd::check(&missing).is_err() && motd::check(&fifo).is_err());
}

#[test]
fn a_hushlogin_in_home_hushes() {
    let home = scratch("hush");
    assert!(!motd::hushed(Some(home.as_os_str())));
    std::fs::write(home.join(".hushlogin"), b"").unwrap();
    assert!(motd::hushed(Some(home.as_os_str())));
    assert!(!motd::hushed(Some(OsStr::new("relative/home"))), "a relative HOME hushes nothing");
    assert!(!motd::hushed(None));
    let file = home.join("motd");
    std::fs::write(&file, b"hello\n").unwrap();
    assert_eq!(motd::shown(&Motd::named(&file), Some(home.as_os_str())), motd::Shown::default());
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a server whose shell is /bin/sh, with `home`
/// as HOME, `file` as the message of the day, and `pty` as its mode.
async fn connect(home: &Path, file: &Path, pty: PtyMode) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = keygen::generate(KeyKind::Ed25519, "test").unwrap();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path), ("HOME".into(), home.as_os_str().into())];
    let settings = Settings {
        base_env: Some(base),
        shell: Some("/bin/sh".into()),
        pty,
        motd: Some(Motd::named(file)),
        ..Settings::default()
    };
    let host = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    tokio::spawn(server::serve_with(far, host, Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// The channel's data until it holds `needle`, or its close.
async fn read_until(channel: &mut Channel<client::Msg>, needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(WAIT, async {
        while !out.windows(needle.len()).any(|w| w == needle) {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => out.extend_from_slice(&data),
                Some(ChannelMsg::Close) | None => return,
                Some(_) => {}
            }
        }
    })
    .await;
    out
}

/// The message of the day of these tests, and its bytes on the terminal.
const TEXT: &[u8] = b"Welcome to the sandbox.\nIt expires at noon.\x1b[2J\n";
const SHOWN: &[u8] = b"Welcome to the sandbox.\r\nIt expires at noon.[2J\r\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_line_discipline_shows_it_before_the_first_prompt_and_a_command_none() {
    let home = scratch("line");
    let file = home.join("motd");
    std::fs::write(&file, TEXT).unwrap();
    let handle = connect(&home, &file, PtyMode::Line).await;

    let mut shell = handle.channel_open_session().await.unwrap();
    shell.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();
    let out = read_until(&mut shell, b"$ ").await;
    let mut want = SHOWN.to_vec();
    want.extend_from_slice(b"$ ");
    assert!(out.starts_with(&want), "the text, then the prompt: {:?}", String::from_utf8_lossy(&out));
    let _ = shell.data(&b"exit 0\r"[..]).await;

    let mut command = handle.channel_open_session().await.unwrap();
    command.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    command.exec(true, "echo COMMAND-RAN").await.unwrap();
    let out = read_until(&mut command, b"COMMAND-RAN").await;
    assert!(!out.windows(9).any(|w| w == b"Welcome t"), "no text for a command: {:?}", String::from_utf8_lossy(&out));

    std::fs::write(home.join(".hushlogin"), b"").unwrap();
    let mut hushed = handle.channel_open_session().await.unwrap();
    hushed.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    hushed.request_shell(true).await.unwrap();
    let out = read_until(&mut hushed, b"$ ").await;
    assert!(out.starts_with(b"$ "), "~/.hushlogin: the prompt alone: {:?}", String::from_utf8_lossy(&out));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pty_shows_it_before_any_byte_of_the_shell() {
    if let Err(why) = pty::open() {
        eprintln!("did not run: no pty here: {why}");
        return;
    }
    let home = scratch("pty");
    let file = home.join("motd");
    std::fs::write(&file, TEXT).unwrap();
    let handle = connect(&home, &file, PtyMode::No).await;
    let mut shell = handle.channel_open_session().await.unwrap();
    shell.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();
    shell.data(&b"echo SHELL-RAN\n"[..]).await.unwrap();
    let out = read_until(&mut shell, b"SHELL-RAN\r\n").await;
    assert!(out.starts_with(SHOWN), "the text first: {:?}", String::from_utf8_lossy(&out));
    let _ = shell.data(&b"exit 0\n"[..]).await;
}
