//! The far end's half of local echo (T-160), with russh's client over a
//! pipe: `podssh serve` takes `env predict@podssh v1` on a channel with a
//! pty, and then reports, on extended data of podssh's own code, the count
//! of the client's bytes that reached the pty and the pty's ECHO and
//! ICANON flags, each report after the output read before it. Without the
//! ask, or without a pty, no report comes. Where no master opens on this
//! host, each test says that it did not run.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::predict::report::{Report, Reports, ENV, EXT, VERSION};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::{self, pty, Authorized, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
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

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a new server, with this host's PATH.
async fn connect() -> client::Handle<Trusting> {
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = Settings { base_env: Some(vec![("PATH".into(), path)]), ..Settings::default() };
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// What a channel gave: its output, its reports with the output's length
/// when each came, and its replies.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    reports: Vec<(Report, usize)>,
    decoder: Reports,
    replies: Vec<bool>,
    other: Vec<u32>,
}

impl Seen {
    fn take(&mut self, message: ChannelMsg) {
        match message {
            ChannelMsg::Data { data } => self.out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext } if ext == EXT => {
                for report in self.decoder.feed(&data).expect("reports of this version") {
                    self.reports.push((report, self.out.len()));
                }
            }
            ChannelMsg::ExtendedData { ext, .. } => self.other.push(ext),
            ChannelMsg::Success => self.replies.push(true),
            ChannelMsg::Failure => self.replies.push(false),
            _ => {}
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }
}

/// Read until `done` holds.
async fn read_until(channel: &mut Channel<client::Msg>, seen: &mut Seen, done: impl Fn(&Seen) -> bool) {
    tokio::time::timeout(LIMIT, async {
        while !done(seen) {
            let Some(message) = channel.wait().await else { panic!("the channel ended: {seen:?}") };
            seen.take(message);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("not in time: {seen:?}"));
}

/// A channel with a pty that asked for the reports, running `command`.
async fn asked(command: &str) -> (client::Handle<Trusting>, Channel<client::Msg>, Seen) {
    let handle = connect().await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 3).await;
    assert_eq!(seen.replies, vec![true, true, true], "the pty, the ask, the command: {seen:?}");
    (handle, channel, seen)
}

/// Under `cat` on a pty that echoes, each key's report comes after its
/// echo, with ECHO and ICANON on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_follows_the_echo_of_the_keys_it_counts() {
    if !have_pty() {
        return;
    }
    let (_kept, mut channel, mut seen) = asked("printf ready; cat").await;
    read_until(&mut channel, &mut seen, |s| s.text().contains("ready")).await;
    channel.data(&b"abc"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.reports.iter().any(|(r, _)| r.offset == 3)).await;
    let (report, after) = seen.reports.iter().find(|(r, _)| r.offset == 3).copied().unwrap();
    assert!(report.flags.echo && report.flags.canonical, "{seen:?}");
    assert!(String::from_utf8_lossy(&seen.out[..after]).ends_with("readyabc"), "the echo first: {seen:?}");
    assert!(seen.reports.windows(2).all(|w| w[0].0.offset <= w[1].0.offset), "counts never go back: {seen:?}");
    assert!(seen.other.is_empty(), "no other extended data: {seen:?}");
}

/// After `stty -echo`, the report says so, and the keys never show.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_line_with_no_echo_is_reported_and_shows_no_key() {
    if !have_pty() {
        return;
    }
    let (_kept, mut channel, mut seen) = asked("stty -echo; printf ready; cat").await;
    read_until(&mut channel, &mut seen, |s| s.reports.iter().any(|(r, _)| r.flags.hidden())).await;
    channel.data(&b"xyz"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.reports.iter().any(|(r, _)| r.offset == 3)).await;
    let (report, _) = seen.reports.iter().find(|(r, _)| r.offset == 3).copied().unwrap();
    assert!(report.flags.hidden(), "ECHO off, ICANON on: {seen:?}");
    assert!(!seen.text().contains("xyz"), "no echo: {seen:?}");
}

/// No pty, another version, or no ask: refused, and no report comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_pty_or_the_ask_no_report_comes() {
    if !have_pty() {
        return;
    }
    let handle = connect().await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, "v2").await.unwrap();
    channel.exec(true, "printf ready; cat").await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 4 && s.text().contains("ready")).await;
    assert_eq!(seen.replies, vec![false, true, false, true], "no pty yet; the pty; v2; the command: {seen:?}");
    channel.data(&b"abc"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.text().contains("abc")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(Some(message)) = tokio::time::timeout(Duration::from_millis(100), channel.wait()).await {
        seen.take(message);
    }
    assert!(seen.reports.is_empty(), "no ask taken, no report: {seen:?}");
}
