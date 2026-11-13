//! `podssh serve` as the line discipline where no pty opens (T-111), with
//! russh's client over a pipe and `--pty line` (`PtyMode::Line`), so that
//! the test runs the same on a host that has a pty: the prompt, each key
//! echoed, a submitted line run by the shell, its output in CR LF, Ctrl-C
//! that ends the command in the foreground and not the shell, the exit
//! status of `exit`, and the note of a program that draws on a tty.

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::{self, Authorized, PtyMode, Settings};

/// A bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(30);

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a new server whose shell is /bin/sh, with
/// `--pty line`.
async fn connect() -> client::Handle<Trusting> {
    connect_with("/bin/sh").await
}

/// As [`connect`], with `shell` as the server's shell.
async fn connect_with(shell: &str) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = keygen::generate(KeyKind::Ed25519, "test").unwrap();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = Settings {
        base_env: Some(vec![("PATH".into(), path)]),
        shell: Some(shell.into()),
        pty: PtyMode::Line,
        ..Settings::default()
    };
    let host: PrivateKey = keygen::generate(KeyKind::Ed25519, "host").unwrap();
    tokio::spawn(server::serve_with(far, host, Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// What a channel gave.
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

    fn take(&mut self, message: ChannelMsg) {
        match message {
            ChannelMsg::Data { data } => self.out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => self.err.extend_from_slice(&data),
            ChannelMsg::Success => self.replies.push(true),
            ChannelMsg::Failure => self.replies.push(false),
            ChannelMsg::ExitStatus { exit_status } => self.status = Some(exit_status),
            ChannelMsg::Close => self.closed = true,
            _ => {}
        }
    }
}

/// Read until the output holds `needle`; the time it took.
async fn read_until(channel: &mut Channel<client::Msg>, seen: &mut Seen, needle: &str) -> Duration {
    let started = Instant::now();
    tokio::time::timeout(LIMIT, async {
        while !seen.text().contains(needle) {
            let Some(message) = channel.wait().await else { panic!("the channel ended before {needle:?}: {seen:?}") };
            seen.take(message);
            assert!(!seen.closed || seen.text().contains(needle), "closed before {needle:?}: {seen:?}");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {needle:?} in time: {seen:?}"));
    started.elapsed()
}

async fn read_to_close(channel: &mut Channel<client::Msg>, seen: &mut Seen) {
    tokio::time::timeout(LIMIT, async {
        while !seen.closed {
            let Some(message) = channel.wait().await else { break };
            seen.take(message);
        }
    })
    .await
    .expect("the channel closes in time");
}

/// A login shell on the line discipline.
async fn shell() -> (client::Handle<Trusting>, Channel<client::Msg>, Seen) {
    shell_of("/bin/sh").await
}

/// A login shell of `path` on the line discipline.
async fn shell_of(path: &str) -> (client::Handle<Trusting>, Channel<client::Msg>, Seen) {
    let handle = connect_with(path).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.request_shell(true).await.unwrap();
    (handle, channel, Seen::default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_prompt_the_echo_and_a_line_s_output_in_cr_lf() {
    let (_kept, mut channel, mut seen) = shell().await;
    read_until(&mut channel, &mut seen, "$ ").await;
    assert_eq!(seen.replies.first(), Some(&true), "the pty is granted: {seen:?}");
    // The shell joins the quotes: the needle is in the output alone, never
    // in the echo of the line.
    channel.data(&b"echo o''ne; echo t''wo\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, "one\r\ntwo\r\n").await;
    let text = seen.text();
    assert!(text.contains("echo o''ne; echo t''wo"), "each key echoed: {text:?}");
    assert!(text.contains("one\r\ntwo\r\n"), "the output's lines in CR LF: {text:?}");
    assert!(!text.replace("\r\n", "").contains('\n'), "no lone LF reaches the client: {text:?}");
    channel.data(&b"exit 9\r"[..]).await.unwrap();
    read_to_close(&mut channel, &mut seen).await;
    assert_eq!(seen.status, Some(9), "{seen:?}");
}

/// Each shell of the host among sh, dash and bash: its trap keeps it
/// alive, and SIGINT reaches the command in the foreground.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_ends_the_command_and_not_the_shell() {
    let shells: Vec<&str> =
        ["/bin/sh", "/bin/dash", "/bin/bash"].into_iter().filter(|p| std::path::Path::new(p).exists()).collect();
    assert!(!shells.is_empty(), "no shell to test");
    for path in shells {
        let (_kept, mut channel, mut seen) = shell_of(path).await;
        read_until(&mut channel, &mut seen, "$ ").await;
        channel.data(&b"sleep 30\r"[..]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let sent = Instant::now();
        channel.data(&b"\x03"[..]).await.unwrap();
        channel.data(&b"echo AFTER-$?\r"[..]).await.unwrap();
        read_until(&mut channel, &mut seen, "AFTER-1").await;
        let took = sent.elapsed();
        read_until(&mut channel, &mut seen, "\r\n$ ").await;
        assert!(took < Duration::from_secs(5), "{path}: Ctrl-C ended sleep in {took:?}: {seen:?}");
        let text = seen.text();
        assert!(text.contains("AFTER-130"), "{path}: sleep ended by SIGINT, the shell goes on: {text:?}");
        channel.data(&b"exit 0\r"[..]).await.unwrap();
        read_to_close(&mut channel, &mut seen).await;
        assert_eq!(seen.status, Some(0), "{path}: {seen:?}");
        println!("{path}: Ctrl-C ended the command in {took:?}, and the shell went on");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_program_that_draws_on_a_tty_gets_a_note_and_runs() {
    let (_kept, mut channel, mut seen) = shell().await;
    read_until(&mut channel, &mut seen, "$ ").await;
    channel.data(&b"less /nonexistent/podssh-file 2>&1; echo DO''NE\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, "DONE").await;
    assert!(seen.text().contains("less needs a pty"), "{seen:?}");
    channel.eof().await.unwrap();
    read_to_close(&mut channel, &mut seen).await;
    assert!(seen.status.is_some(), "the client's EOF ends the shell's input: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_on_the_line_discipline_has_no_tty_and_its_term() {
    let handle = connect().await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "vt100", 100, 30, 0, 0, &[]).await.unwrap();
    channel.exec(true, r#"test -t 0 || echo PIPES; echo "TERM=$TERM SSH_TTY=${SSH_TTY-unset}""#).await.unwrap();
    let mut seen = Seen::default();
    read_to_close(&mut channel, &mut seen).await;
    assert_eq!(seen.replies, vec![true, true], "{seen:?}");
    assert!(seen.text().contains("PIPES\r\nTERM=vt100 SSH_TTY=unset\r\n"), "{seen:?}");
    assert_eq!(seen.status, Some(0), "{seen:?}");
}
