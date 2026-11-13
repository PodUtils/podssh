//! A pty of `podssh serve` (T-110), with russh's client over a pipe: where a
//! master opens on this host, a `pty-req` is granted, and the command sees a
//! terminal (`tty` names a slave under /dev, `SSH_TTY` the same, `TERM` the
//! request's); `stty size` gives the asked size, 80x24 for a zero one, and
//! follows a `window-change`; the request's modes are set; Ctrl-C on the
//! pty interrupts the command; stdout and stderr come as one stream; each
//! byte comes before the end; the client's EOF does not cut the output.
//! Where no master opens here, each test says that it did not run; the
//! refusal is `serve_exec`'s, with a master that is missing. The same
//! against OpenSSH's client: `podssh-cli`'s `tests/serve_openssh.rs`.

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel, ChannelMsg, Pty};
use podssh_ssh::server::{self, pty, Authorized, Settings};

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

/// A logged-in connection to a new server, with this host's PATH.
async fn connect() -> client::Handle<Trusting> {
    connect_with(|settings| settings).await
}

/// As [`connect`], with the server's settings changed by `change`.
async fn connect_with(change: impl FnOnce(Settings) -> Settings) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = change(Settings { base_env: Some(vec![("PATH".into(), path)]), ..Settings::default() });
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// What a channel gave until its close.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    err: Vec<u8>,
    replies: Vec<bool>,
    status: Option<u32>,
    signal: Option<String>,
    order: Vec<&'static str>,
}

impl Seen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    /// The lines of the output, without the pty's carriage returns.
    fn lines(&self) -> Vec<String> {
        self.text().lines().map(|l| l.trim_end_matches('\r').to_string()).collect()
    }

    /// Take one message; true at the close.
    fn take(&mut self, message: ChannelMsg) -> bool {
        match message {
            ChannelMsg::Data { data } => {
                self.out.extend_from_slice(&data);
                self.order.push("data");
            }
            ChannelMsg::ExtendedData { data, .. } => self.err.extend_from_slice(&data),
            ChannelMsg::Success => self.replies.push(true),
            ChannelMsg::Failure => self.replies.push(false),
            ChannelMsg::ExitStatus { exit_status } => {
                self.status = Some(exit_status);
                self.order.push("exit");
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                self.signal = Some(podssh_ssh::signals::name(&signal_name));
                self.order.push("exit");
            }
            ChannelMsg::Eof => self.order.push("eof"),
            ChannelMsg::Close => {
                self.order.push("close");
                return true;
            }
            _ => {}
        }
        false
    }
}

async fn read_to_close(channel: &mut Channel<client::Msg>, seen: &mut Seen) {
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            if seen.take(message) {
                break;
            }
        }
    })
    .await
    .expect("the channel closes in time");
}

/// Read until the output holds `needle`.
async fn read_until(channel: &mut Channel<client::Msg>, seen: &mut Seen, needle: &str) {
    tokio::time::timeout(LIMIT, async {
        while !seen.text().contains(needle) {
            let Some(message) = channel.wait().await else { panic!("the channel ended before {needle:?}: {seen:?}") };
            if seen.take(message) {
                panic!("the channel closed before {needle:?}: {seen:?}");
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {needle:?} in time: {seen:?}"));
}

/// The connection, kept for as long as its channel is read.
type Kept = client::Handle<Trusting>;

/// A channel with a pty of `cols` by `rows` and `modes`, running `command`.
async fn on_pty(cols: u32, rows: u32, modes: &[(Pty, u32)], command: &str) -> (Kept, Channel<client::Msg>, Seen) {
    let handle = connect().await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "vt100", cols, rows, 0, 0, modes).await.unwrap();
    channel.exec(true, command).await.unwrap();
    (handle, channel, Seen::default())
}

/// Each byte, then one exit message, then EOF, then close.
fn ended_in_order(seen: &Seen) {
    let at = |what: &str| seen.order.iter().position(|o| *o == what);
    let last_data = seen.order.iter().rposition(|o| *o == "data");
    let (exit, eof, close) = (at("exit"), at("eof"), at("close"));
    assert!(exit.is_some() && eof.is_some() && close.is_some(), "{seen:?}");
    assert!(exit < eof && eof < close, "exit, EOF, close: {seen:?}");
    assert!(last_data.is_none_or(|d| Some(d) < exit), "each byte before the exit: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pty_is_granted_and_the_command_sees_a_terminal() {
    if !have_pty() {
        return;
    }
    let command = r#"tty; stty size; echo "TERM=$TERM"; test "$SSH_TTY" = "$(tty)" && echo same; echo err >&2"#;
    let (_kept, mut channel, mut seen) = on_pty(100, 30, &[], command).await;
    read_to_close(&mut channel, &mut seen).await;
    assert_eq!(seen.replies, vec![true, true], "the pty, then the command: {seen:?}");
    let lines = seen.lines();
    assert!(lines.first().is_some_and(|l| l.starts_with("/dev/")), "tty names a slave: {seen:?}");
    assert_eq!(lines.get(1).map(String::as_str), Some("30 100"), "{seen:?}");
    assert_eq!(lines.get(2).map(String::as_str), Some("TERM=vt100"), "{seen:?}");
    assert_eq!(lines.get(3).map(String::as_str), Some("same"), "SSH_TTY names the slave: {seen:?}");
    assert_eq!(lines.get(4).map(String::as_str), Some("err"), "stderr is the pty too: {seen:?}");
    assert!(seen.err.is_empty(), "no stderr apart on a pty: {seen:?}");
    assert!(seen.text().contains("\r\n"), "the pty's ONLCR: {seen:?}");
    assert_eq!(seen.status, Some(0), "{seen:?}");
    ended_in_order(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_size_is_80_by_24_and_a_second_pty_is_refused() {
    if !have_pty() {
        return;
    }
    let handle = connect().await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "", 0, 0, 0, 0, &[]).await.unwrap();
    channel.request_pty(true, "xterm", 90, 20, 0, 0, &[]).await.unwrap();
    channel.exec(true, r#"stty size; echo "TERM=$TERM""#).await.unwrap();
    let mut seen = Seen::default();
    read_to_close(&mut channel, &mut seen).await;
    assert_eq!(seen.replies, vec![true, false, true], "one pty for each channel: {seen:?}");
    assert_eq!(seen.lines(), vec!["24 80".to_string(), "TERM=xterm-256color".to_string()], "{seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_size_follows_a_window_change() {
    if !have_pty() {
        return;
    }
    let (_kept, mut channel, mut seen) = on_pty(100, 30, &[], "stty size; read line; stty size").await;
    read_until(&mut channel, &mut seen, "30 100").await;
    channel.window_change(120, 40, 0, 0).await.unwrap();
    // Enter, as a terminal sends it: ICRNL makes it a newline.
    channel.data(&b"go\r"[..]).await.unwrap();
    read_to_close(&mut channel, &mut seen).await;
    assert!(seen.lines().iter().any(|l| l == "40 120"), "the new size: {seen:?}");
    assert_eq!(seen.status, Some(0), "{seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_modes_of_the_request_are_set() {
    if !have_pty() {
        return;
    }
    let modes = [(Pty::ECHO, 0), (Pty::VERASE, 8), (Pty::VINTR, 3)];
    let (_kept, mut channel, mut seen) = on_pty(80, 24, &modes, "stty -a").await;
    read_to_close(&mut channel, &mut seen).await;
    let text = seen.text();
    let words: Vec<&str> = text.split(|c: char| c.is_whitespace() || c == ';').collect();
    assert!(words.contains(&"-echo"), "ECHO off: {text}");
    assert!(text.contains("erase = ^H"), "VERASE 8: {text}");
    assert!(text.contains("intr = ^C"), "VINTR 3: {text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_on_the_pty_interrupts_the_command() {
    if !have_pty() {
        return;
    }
    let modes = [(Pty::ISIG, 1), (Pty::VINTR, 3)];
    let (_kept, mut channel, mut seen) = on_pty(80, 24, &modes, "echo ready; sleep 25").await;
    read_until(&mut channel, &mut seen, "ready").await;
    let started = Instant::now();
    // The pty, not a signal request: the slave is the child's controlling
    // terminal, and its group the foreground one. Again each second, as a
    // person presses it: the first can land while the shell has forked the
    // sleep and not yet exec'd it, when the child still runs the shell's
    // handler, and the shell then waits for the sleep (a race of the test's
    // shell, not of the pty).
    let mut closed = false;
    for _ in 0..15 {
        channel.data(&b"\x03"[..]).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(message) = channel.wait().await {
                if seen.take(message) {
                    return true;
                }
            }
            true
        });
        if let Ok(true) = ended.await {
            closed = true;
            break;
        }
    }
    assert!(closed, "the channel closed after Ctrl-C: {seen:?}");
    assert!(started.elapsed() < Duration::from_secs(20), "Ctrl-C ended it, not the sleep: {seen:?}");
    let interrupted = seen.signal.as_deref() == Some("INT") || seen.status == Some(130);
    assert!(interrupted, "SIGINT, or a shell's 130: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_byte_comes_before_the_end_and_eof_cuts_nothing() {
    if !have_pty() {
        return;
    }
    let (_kept, mut channel, mut seen) = on_pty(80, 24, &[], "sleep 1; yes podssh | head -n 20000").await;
    // The client's EOF ends its writing alone: a pty has no half-close.
    channel.eof().await.unwrap();
    read_to_close(&mut channel, &mut seen).await;
    assert_eq!(seen.lines().iter().filter(|l| *l == "podssh").count(), 20000, "{} bytes", seen.out.len());
    assert_eq!(seen.status, Some(0), "{seen:?}");
    ended_in_order(&seen);
}

/// Route 1 (T-775): with no master of the host's, a devpts instance of
/// podssh's own serves the request where the host lets serve make one: a
/// terminal of the request's size, no `SSH_TTY` (its slave has no path),
/// and a window change that reaches the child's trap. Where the host
/// refuses the instance, the request is refused, as before.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn devpts_with_no_master_a_pty_of_its_own_instance_serves_the_request() {
    let here = podssh_ssh::server::pty_devpts::open();
    if let Err(why) = &here {
        eprintln!("did not run: no devpts instance here ({why}); the refusal is tested");
    }
    let handle = connect_with(|s| Settings { ptmx: Some(vec![]), devpts: Some(true), ..s }).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "vt100", 132, 43, 0, 0, &[]).await.unwrap();
    let mut seen = Seen::default();
    if here.is_err() {
        channel.exec(true, "test -t 0 && echo ISATTY; echo pipes").await.unwrap();
        read_to_close(&mut channel, &mut seen).await;
        assert_eq!(seen.replies, vec![false, true], "no instance: the pty refused, the command on pipes: {seen:?}");
        assert_eq!(seen.lines(), vec!["pipes".to_string()], "{seen:?}");
        return;
    }
    let command = r#"test -t 0 && echo ISATTY; stty size; echo "SSH_TTY=${SSH_TTY-unset}"; trap 'stty size; exit 0' WINCH; echo ready; while :; do sleep 1; done"#;
    channel.exec(true, command).await.unwrap();
    read_until(&mut channel, &mut seen, "ready").await;
    assert_eq!(seen.replies.first(), Some(&true), "the pty is granted: {seen:?}");
    let lines = seen.lines();
    assert!(lines.iter().any(|l| l == "ISATTY"), "the child has a terminal: {seen:?}");
    assert!(lines.iter().any(|l| l == "43 132"), "the request's size: {seen:?}");
    assert!(lines.iter().any(|l| l == "SSH_TTY=unset"), "no path, no SSH_TTY: {seen:?}");
    channel.window_change(100, 30, 0, 0).await.unwrap();
    read_to_close(&mut channel, &mut seen).await;
    assert!(seen.lines().iter().any(|l| l == "30 100"), "the trap saw the new size: {seen:?}");
    assert_eq!(seen.status, Some(0), "{seen:?}");
}
