//! Local echo's reports from a kept shell (T-896), with russh's client over
//! pipes in memory: each channel that has a kept shell and asked with `env
//! predict@podssh v1` gets the reports of its own bytes, counted from its
//! attach as the client counts them, each after the output read before it;
//! a channel that did not ask gets none. A key that makes no output (a
//! line with no echo) is reported to a channel that attached after the
//! shell's pump began to wait. Each case needs a pty; a host with none says
//! so.

#![cfg(unix)]

mod kept_harness;
mod share_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::predict::report::{Report, Reports, ENV, EXT, VERSION};
use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::russh::{ChannelMsg, ChannelWriteHalf};
use share_harness::{have_pty, key, Server, LIMIT};

/// What one channel gave: its output, its reports with the output's length
/// when each came, and its replies.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    reports: Vec<(Report, usize)>,
    decoder: Reports,
    replies: Vec<bool>,
    closed: bool,
}

impl Seen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    fn report_of(&self, offset: u64) -> Option<(Report, usize)> {
        self.reports.iter().find(|(r, _)| r.offset == offset).copied()
    }
}

/// A channel's writing half, and what its reader saw.
struct Channel {
    write: ChannelWriteHalf<podssh_ssh::russh::client::Msg>,
    seen: Arc<Mutex<Seen>>,
    _kept: podssh_ssh::russh::client::Handle<share_harness::Trusting>,
}

impl Channel {
    /// A login shell of `login` on a pty, after the `env` requests `asks`.
    async fn shell(server: &Server, login: &PrivateKey, asks: &[(&str, &str)]) -> Channel {
        let handle = server.login("user", login).await.expect("the key logs in");
        let (mut read, write) = handle.channel_open_session().await.unwrap().split();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let into = seen.clone();
        tokio::spawn(async move {
            while let Some(message) = read.wait().await {
                let mut seen = into.lock().unwrap();
                match message {
                    ChannelMsg::Data { data } => seen.out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext } if ext == EXT => {
                        let at = seen.out.len();
                        let reports = seen.decoder.feed(&data).expect("reports of this version");
                        seen.reports.extend(reports.into_iter().map(|report| (report, at)));
                    }
                    ChannelMsg::Success => seen.replies.push(true),
                    ChannelMsg::Failure => seen.replies.push(false),
                    ChannelMsg::Close => {
                        seen.closed = true;
                        break;
                    }
                    _ => {}
                }
            }
        });
        write.request_pty(true, "vt100", 80, 24, 0, 0, &[]).await.unwrap();
        for (name, value) in asks {
            write.set_env(true, *name, *value).await.unwrap();
        }
        write.request_shell(true).await.unwrap();
        let channel = Channel { write, seen, _kept: handle };
        let replies = asks.len() + 2;
        channel.until("each reply", |seen| seen.replies.len() >= replies).await;
        assert!(channel.seen.lock().unwrap().replies.iter().all(|r| *r), "{:?}", channel.seen.lock().unwrap());
        channel
    }

    async fn send(&self, bytes: &[u8]) {
        self.write.data(bytes).await.unwrap();
    }

    async fn until(&self, name: &str, what: impl Fn(&Seen) -> bool) {
        let waited = tokio::time::timeout(LIMIT, async {
            while !what(&self.seen.lock().unwrap()) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "no {name} in time: {:?}", self.seen.lock().unwrap());
    }

    /// Keep the shell as `name`, and wait for the channel's close.
    async fn detach(&self, name: &str) {
        let before = self.seen.lock().unwrap().replies.len();
        self.write.set_env(true, "detach@podssh", name).await.unwrap();
        self.until("the detach's reply", |seen| seen.replies.len() > before).await;
        assert!(self.seen.lock().unwrap().replies[before], "the far end keeps the shell");
        self.until("the channel's close", |seen| seen.closed).await;
    }
}

/// The first channel asked: its reports count its keys; detached and
/// joined again by a channel that asked, the new channel's reports count
/// its own keys from 0, each after their echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_channel_of_a_kept_shell_gets_the_reports_of_its_own_keys() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = kept_harness::server(Duration::from_secs(600), &[&owner]);
    let first = Channel::shell(&server, &owner, &[(ENV, VERSION)]).await;
    // cat on a pty that echoes: each key's echo is the kernel's.
    first.send(b"exec cat\r").await;
    first.until("cat's start", |seen| seen.report_of(9).is_some()).await;
    first.send(b"abc").await;
    first.until("the report of abc", |seen| seen.report_of(12).is_some()).await;
    {
        let seen = first.seen.lock().unwrap();
        let (report, after) = seen.report_of(12).unwrap();
        assert!(report.flags.echo && report.flags.canonical, "cat's pty echoes a line: {seen:?}");
        assert!(String::from_utf8_lossy(&seen.out[..after]).ends_with("abc"), "the echo first: {seen:?}");
    }
    first.detach("work").await;

    let second = Channel::shell(&server, &owner, &[("attach@podssh", "work"), (ENV, VERSION)]).await;
    second.send(b"xyz").await;
    second.until("the report of xyz", |seen| seen.report_of(3).is_some()).await;
    let seen = second.seen.lock().unwrap();
    let (report, after) = seen.report_of(3).unwrap();
    assert!(report.flags.echo && report.flags.canonical, "{seen:?}");
    assert!(String::from_utf8_lossy(&seen.out[..after]).ends_with("xyz"), "the echo first: {seen:?}");
    assert!(seen.reports.iter().all(|(r, _)| r.offset <= 3), "the channel's own count, from 0: {seen:?}");
}

/// A first channel that did not ask gets no report. A channel that joins
/// with the ask, where the shell reads a line with no echo, gets the
/// report of its keys, which make no output: the pump, which waited with
/// no reporter, waits on the new channel's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_with_no_echo_is_reported_to_a_channel_that_joined() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = kept_harness::server(Duration::from_secs(600), &[&owner]);
    let first = Channel::shell(&server, &owner, &[]).await;
    first.send(b"stty -echo; echo QUIET_$((6*7))_END; exec cat\r").await;
    first.until("the shell's answer", |seen| seen.text().contains("QUIET_42_END")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(first.seen.lock().unwrap().reports.is_empty(), "no ask, no report: {:?}", first.seen.lock().unwrap());
    first.detach("quiet").await;

    let second = Channel::shell(&server, &owner, &[("attach@podssh", "quiet"), (ENV, VERSION)]).await;
    // Let the catch-up end, so that the keys come to a pump that waits.
    tokio::time::sleep(Duration::from_millis(500)).await;
    second.send(b"pw").await;
    second.until("the report of pw", |seen| seen.report_of(2).is_some()).await;
    let seen = second.seen.lock().unwrap();
    let (report, _) = seen.report_of(2).unwrap();
    assert!(report.flags.hidden(), "a line with no echo: {seen:?}");
    assert!(!seen.text().contains("pw"), "no echo: {seen:?}");
}
