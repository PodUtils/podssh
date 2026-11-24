//! The shell integration marks of `podssh serve --shell-integration`
//! (T-120): the bytes of the marks on serve's line discipline, the start
//! files of bash and zsh, and, with russh's client over a pipe, the marks of
//! a login shell on the line discipline and on a pty (bash and zsh where
//! this host has them), the user's start files unchanged, and serve's files
//! gone at the session's end. Without the flag, no mark.

#![cfg(unix)]

mod cleanup;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::PrivateKeyWithHashAlg;
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::marks::{self, Shell, A, B, C, D};
use podssh_ssh::server::{self, pty, Authorized, PtyMode, Settings};

/// A bound on each wait of a test.
const WAIT: Duration = Duration::from_secs(30);

/// The mark of OSC 133 that each marked output holds.
const ANY_MARK: &[u8] = b"\x1b]133;";

/// A directory of this test, removed when it ends.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-marks-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir.canonicalize().unwrap()
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_bytes_of_the_marks() {
    assert_eq!(marks::first_prompt(b"$ "), b"\x1b]133;A\x07$ \x1b]133;B\x07");
    let echo = marks::submitted(b"\r\n$ ", b"$ ").expect("an echo that ends with the prompt");
    assert_eq!(echo, b"\r\n\x1b]133;C\x07\x1b]133;D\x07\x1b]133;A\x07$ \x1b]133;B\x07");
    assert_eq!(marks::submitted(b"ls", b"$ "), None, "an echo of a key");
    assert_eq!(marks::submitted(b"\r\n", b""), None, "no prompt, no mark");
    #[rustfmt::skip]
    let quoted: &[(&[u8], &[u8])] = &[
        (b"/home/u/z", b"'/home/u/z'"),
        (b"it's", b"'it'\\''s'"),
        (b"$HOME `x` \"y\"", b"'$HOME `x` \"y\"'"),
    ];
    for (raw, want) in quoted {
        assert_eq!(marks::single_quoted(raw), *want, "{}", String::from_utf8_lossy(raw));
    }
    assert_eq!(marks::zdotdir_line(None), b"unset ZDOTDIR\n");
    assert_eq!(marks::zdotdir_line(Some(OsStr::new(""))), b"unset ZDOTDIR\n");
    assert_eq!(marks::zdotdir_line(Some(OsStr::new("/a b"))), b"ZDOTDIR='/a b'\n");
}

#[test]
fn bash_and_zsh_get_files_and_others_none() {
    #[rustfmt::skip]
    let shells: &[(&str, Option<Shell>)] = &[
        ("/bin/bash", Some(Shell::Bash)), ("/usr/local/bin/zsh", Some(Shell::Zsh)),
        ("/bin/sh", None), ("/bin/dash", None), ("/usr/bin/fish", None), ("/", None),
    ];
    for (path, want) in shells {
        assert_eq!(Shell::of(Path::new(path)), *want, "{path}");
    }
    assert_eq!(marks::tmp_of(Some(OsStr::new("relative"))), Path::new("/tmp"));
    assert_eq!(marks::tmp_of(None), Path::new("/tmp"));

    let tmp = scratch("files");
    let bash = marks::files(Shell::Bash, &tmp, None).expect("bash's files");
    assert_eq!(bash.arg0.as_deref(), Some(OsStr::new("bash")), "no dash: bash reads --rcfile then");
    assert_eq!(bash.args.first().map(OsString::as_os_str), Some(OsStr::new("--rcfile")));
    let rc = std::fs::read_to_string(&bash.args[1]).unwrap();
    assert!(rc.contains("133;A") && rc.contains("7;file://") && rc.contains("~/.bash_profile"), "{rc}");
    let dir = bash.dir.clone();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    drop(bash);
    assert!(!dir.exists(), "the files go with the session");

    let zsh = marks::files(Shell::Zsh, &tmp, Some(OsStr::new("/home/u/.config/zsh"))).expect("zsh's files");
    assert_eq!(zsh.env, vec![(OsString::from("ZDOTDIR"), zsh.dir.clone().into_os_string())]);
    let env = std::fs::read(zsh.dir.join(".zshenv")).unwrap();
    assert!(env.starts_with(b"ZDOTDIR='/home/u/.config/zsh'\n"), "{}", String::from_utf8_lossy(&env));
    assert!(marks::files(Shell::Bash, &tmp.join("missing"), None).is_err(), "no directory: an error, not a panic");
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a server whose shell is `shell`, with `home`
/// as HOME and `tmp` as TMPDIR.
async fn connect(shell: &str, home: &Path, tmp: &Path, pty: PtyMode, on: bool) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = keygen::generate(KeyKind::Ed25519, "test").unwrap();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let base: Vec<(OsString, OsString)> = vec![
        ("PATH".into(), path),
        ("HOME".into(), home.as_os_str().into()),
        ("TMPDIR".into(), tmp.as_os_str().into()),
    ];
    let settings =
        Settings { base_env: Some(base), shell: Some(shell.into()), pty, shell_integration: on, ..Settings::default() };
    let host = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    tokio::spawn(server::serve_with(far, host, Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// A login shell on a tty of `pty`'s kind.
async fn login(handle: &client::Handle<Trusting>) -> Channel<client::Msg> {
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.request_shell(true).await.unwrap();
    channel
}

/// Read into `out` until it holds `needle`, or the channel closes; true
/// at the close.
async fn read_until(channel: &mut Channel<client::Msg>, out: &mut Vec<u8>, needle: &[u8]) -> bool {
    let read = tokio::time::timeout(WAIT, async {
        while needle.is_empty() || !holds(out, needle) {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => out.extend_from_slice(&data),
                Some(ChannelMsg::Close) | None => return true,
                Some(_) => {}
            }
        }
        false
    })
    .await;
    read.unwrap_or_else(|_| {
        panic!("no {:?} in time: {:?}", String::from_utf8_lossy(needle), String::from_utf8_lossy(out))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_line_discipline_marks_its_prompts_and_lines() {
    let (home, tmp) = (scratch("line-home"), scratch("line-tmp"));
    let handle = connect("/bin/sh", &home, &tmp, PtyMode::Line, true).await;
    let mut shell = login(&handle).await;
    let mut out = Vec::new();
    read_until(&mut shell, &mut out, B).await;
    assert!(out.starts_with(&marks::first_prompt(b"$ ")), "{:?}", String::from_utf8_lossy(&out));
    shell.data(&b"echo o''k\r"[..]).await.unwrap();
    read_until(&mut shell, &mut out, b"ok\r\n").await;
    let next = [C, D, A, &b"$ "[..], B].concat();
    assert!(holds(&out, &next), "the line's end and the next prompt: {:?}", String::from_utf8_lossy(&out));
    shell.data(&b"exit 0\r"[..]).await.unwrap();
    read_until(&mut shell, &mut out, b"").await;

    let plain = connect("/bin/sh", &home, &tmp, PtyMode::Line, false).await;
    let mut shell = login(&plain).await;
    let mut out = Vec::new();
    read_until(&mut shell, &mut out, b"$ ").await;
    shell.data(&b"echo o''k\r"[..]).await.unwrap();
    read_until(&mut shell, &mut out, b"ok\r\n").await;
    assert!(!holds(&out, ANY_MARK), "no flag, no mark: {:?}", String::from_utf8_lossy(&out));
}

/// The first of `paths` that this host has.
fn shell_of(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|p| Path::new(p).exists())
}

/// A login shell of `shell` on a pty with the flag: the marks and OSC 7,
/// the variable that the user's file set, the user's files unchanged, and
/// serve's files gone after the end.
async fn marks_on_a_pty(shell: &str, files: &[(&str, &str)], ask: &[u8]) {
    let (home, tmp) = (scratch("pty-home"), scratch("pty-tmp"));
    for (name, text) in files {
        std::fs::write(home.join(name), text).unwrap();
    }
    let before: Vec<Vec<u8>> = files.iter().map(|(name, _)| std::fs::read(home.join(name)).unwrap()).collect();
    let handle = connect(shell, &home, &tmp, PtyMode::No, true).await;
    let mut channel = login(&handle).await;
    let mut out = Vec::new();
    read_until(&mut channel, &mut out, A).await;
    channel.data(ask).await.unwrap();
    read_until(&mut channel, &mut out, b"FROM-USER=yes").await;
    // The shell knows the status: D with it, before the next prompt.
    read_until(&mut channel, &mut out, b"\x1b]133;D;0\x07").await;
    assert!(holds(&out, b"\x1b]7;file://"), "{shell}: OSC 7: {:?}", String::from_utf8_lossy(&out));
    assert!(holds(&out, C), "{shell}: the output's start: {:?}", String::from_utf8_lossy(&out));
    channel.data(&b"exit 0\n"[..]).await.unwrap();
    assert!(read_until(&mut channel, &mut out, b"").await, "{shell}: the session ends");
    let after: Vec<Vec<u8>> = files.iter().map(|(name, _)| std::fs::read(home.join(name)).unwrap()).collect();
    assert_eq!(before, after, "{shell}: the user's start files are as they were");
    // The files go once the child's end is served, just after the close.
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::read_dir(&tmp).unwrap().next().is_some() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(std::fs::read_dir(&tmp).unwrap().next().is_none(), "{shell}: serve's files are gone");
}

fn have_pty() -> bool {
    match pty::open() {
        Ok(_) => true,
        Err(why) => {
            eprintln!("did not run: no pty here: {why}");
            false
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bash_on_a_pty_is_marked_and_its_files_are_untouched() {
    let Some(bash) = shell_of(&["/bin/bash", "/usr/bin/bash"]).filter(|_| have_pty()) else {
        eprintln!("did not run: no bash or no pty here");
        return;
    };
    let files = [(".profile", "[ -r ~/.bashrc ] && . ~/.bashrc\n"), (".bashrc", "export FROM_USER=yes\n")];
    marks_on_a_pty(bash, &files, b"echo FROM-USER=$FROM_USER\n").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zsh_on_a_pty_is_marked_and_its_files_are_untouched() {
    let Some(zsh) = shell_of(&["/bin/zsh", "/usr/bin/zsh"]).filter(|_| have_pty()) else {
        eprintln!("did not run: no zsh or no pty here");
        return;
    };
    let files = [(".zshenv", "export FROM_USER=yes\n"), (".zshrc", "PS1='zsh%# '\n")];
    marks_on_a_pty(zsh, &files, b"echo FROM-USER=$FROM_USER\n").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_shell_and_no_flag_get_no_mark() {
    if !have_pty() {
        return;
    }
    let (home, tmp) = (scratch("none-home"), scratch("none-tmp"));
    for (shell, on) in [("/bin/sh", true), (shell_of(&["/bin/bash", "/usr/bin/bash"]).unwrap_or("/bin/sh"), false)] {
        let handle = connect(shell, &home, &tmp, PtyMode::No, on).await;
        let mut channel = login(&handle).await;
        channel.data(&b"echo DO''NE\n"[..]).await.unwrap();
        let mut out = Vec::new();
        read_until(&mut channel, &mut out, b"DONE").await;
        assert!(!holds(&out, ANY_MARK), "{shell}, flag {on}: {:?}", String::from_utf8_lossy(&out));
        assert!(std::fs::read_dir(&tmp).unwrap().next().is_none(), "{shell}: no file made");
        let _ = channel.data(&b"exit 0\n"[..]).await;
    }
}
