//! Local echo's reports from a shell shared by name (T-896), with russh's
//! client over pipes in memory, on each tty that the host gives (T-861):
//! the owner and a writing seat that asked with `env predict@podssh v1`
//! each get the count of their own keys, and each report comes after the
//! echo of each key that it counts; a writing seat that did not ask gets
//! none, and a watcher's ask is refused, as its keys go nowhere. A key
//! with no echo is reported to the seat that typed it, where the shell can
//! turn its echo off (each tty but the line discipline). A tty that the
//! host does not give is said, and its cases do not run.

#![cfg(unix)]

mod share_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::predict::report::{Report, Reports, ENV, EXT, VERSION};
use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::russh::{client, ChannelMsg, ChannelWriteHalf};
use share_harness::{key, Server, Trusting, Tty, LIMIT};

/// What one channel gave: its output, its stderr, its reports with the
/// output's length when each came, and its replies.
#[derive(Debug, Default)]
struct Seen {
    out: Vec<u8>,
    err: Vec<u8>,
    reports: Vec<(Report, usize)>,
    decoder: Reports,
    replies: Vec<bool>,
}

impl Seen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    fn report_of(&self, offset: u64) -> Option<(Report, usize)> {
        self.reports.iter().find(|(r, _)| r.offset == offset).copied()
    }
}

/// One send: the channel's count after it, where its output stood then,
/// and the keys.
struct Sent {
    end: u64,
    at: usize,
    keys: Vec<u8>,
}

/// A seat's channel, what its reader saw, and what it sent.
struct Channel {
    write: ChannelWriteHalf<client::Msg>,
    seen: Arc<Mutex<Seen>>,
    sent: Mutex<Vec<Sent>>,
    _kept: client::Handle<Trusting>,
}

impl Channel {
    /// The login shell of `user` with `login`, on a pty, with the ask where
    /// `ask`: each reply, in the order pty, ask, shell.
    async fn shell(server: &Server, user: &str, login: &PrivateKey, ask: bool) -> Channel {
        let handle = server.login(user, login).await.expect("the login is let in");
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
                    ChannelMsg::ExtendedData { data, .. } => seen.err.extend_from_slice(&data),
                    ChannelMsg::Success => seen.replies.push(true),
                    ChannelMsg::Failure => seen.replies.push(false),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        });
        write.request_pty(true, "vt100", 80, 24, 0, 0, &[]).await.unwrap();
        if ask {
            write.set_env(true, ENV, VERSION).await.unwrap();
        }
        write.request_shell(true).await.unwrap();
        let channel = Channel { write, seen, sent: Mutex::new(Vec::new()), _kept: handle };
        let replies = if ask { 3 } else { 2 };
        channel.until("each reply", |seen| seen.replies.len() >= replies).await;
        channel
    }

    fn replies(&self) -> Vec<bool> {
        self.seen.lock().unwrap().replies.clone()
    }

    async fn send(&self, keys: &[u8]) {
        {
            let mut sent = self.sent.lock().unwrap();
            let end = sent.last().map_or(0, |s| s.end) + keys.len() as u64;
            let at = self.seen.lock().unwrap().out.len();
            sent.push(Sent { end, at, keys: keys.to_vec() });
        }
        self.write.data(keys).await.unwrap();
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

    /// Each report of this channel came after the echo of each printable
    /// key that it counts, in the output from that key's send on.
    fn echo_first(&self, tty: Tty) {
        let seen = self.seen.lock().unwrap();
        let sent = self.sent.lock().unwrap();
        for (report, after) in &seen.reports {
            for send in sent.iter().filter(|s| s.end <= report.offset) {
                let mut keys = send.keys.iter().filter(|k| k.is_ascii_graphic() || **k == b' ');
                // In order, with whatever the tty drew between them.
                let mut rest = seen.out[send.at.min(*after)..*after].iter();
                let echoed = keys.all(|k| rest.any(|b| b == k));
                let (typed, offset) = (String::from_utf8_lossy(&send.keys), report.offset);
                assert!(echoed, "{tty:?}: the report of {offset} came before the echo of {typed:?}: {seen:?}");
            }
        }
    }
}

/// The two names that the owner read on its stderr.
fn names(owner: &Channel) -> (String, String) {
    let err = String::from_utf8_lossy(&owner.seen.lock().unwrap().err).into_owned();
    let name = |prefix: &str| {
        let word = err.split_whitespace().find(|w| w.starts_with(prefix));
        word.unwrap_or_else(|| panic!("no {prefix} name: {err}")).to_string()
    };
    (name("rw-"), name("ro-"))
}

/// The owner, a writer and a watcher that asked, and a writer that did not.
async fn seats(server: &Server, tty: Tty) -> (Channel, Channel, Channel, Channel) {
    let owner = Channel::shell(server, "owner", &server.owner, true).await;
    assert_eq!(owner.replies(), vec![true, true, true], "{tty:?}: the owner's pty, ask and shell");
    owner.until("the names", |seen| String::from_utf8_lossy(&seen.err).contains("watches it")).await;
    let (write, read) = names(&owner);
    let writer = Channel::shell(server, &write, &key(), true).await;
    assert_eq!(writer.replies(), vec![true, true, true], "{tty:?}: a writer's ask is taken");
    let silent = Channel::shell(server, &write, &key(), false).await;
    let watcher = Channel::shell(server, &read, &key(), true).await;
    assert_eq!(watcher.replies(), vec![true, false, true], "{tty:?}: a watcher's ask is refused");
    (owner, writer, silent, watcher)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_seat_that_asked_gets_its_own_count_after_the_echo() {
    for tty in Tty::here() {
        own_counts_on(tty).await;
    }
}

async fn own_counts_on(tty: Tty) {
    let server = Server::on(tty);
    let (owner, writer, silent, watcher) = seats(&server, tty).await;
    // cat on a tty that echoes: each key's echo is the tty's own.
    owner.send(b"exec cat\r").await;
    owner.until("the owner's report", |seen| seen.report_of(9).is_some()).await;
    // Past the owner's lease, so the writer's keys reach the tty at once.
    tokio::time::sleep(Duration::from_millis(500)).await;
    writer.send(b"abc").await;
    writer.until("the writer's report", |seen| seen.report_of(3).is_some()).await;
    let (report, _) = writer.seen.lock().unwrap().report_of(3).unwrap();
    assert!(report.flags.echo && report.flags.canonical, "{tty:?}: cat's tty echoes a line: {report:?}");

    tokio::time::sleep(Duration::from_millis(500)).await;
    silent.send(b"xyz").await;
    silent.until("the echo of xyz", |seen| seen.text().contains("xyz")).await;
    writer.until("the echo of xyz", |seen| seen.text().contains("xyz")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    for (who, seat) in [("a seat that did not ask", &silent), ("a watcher", &watcher)] {
        assert!(seat.seen.lock().unwrap().reports.is_empty(), "{tty:?}: {who} gets no report");
    }
    let writer_seen = writer.seen.lock().unwrap();
    assert!(writer_seen.reports.iter().all(|(r, _)| r.offset <= 3), "{tty:?}: its own count: {writer_seen:?}");
    let owner_seen = owner.seen.lock().unwrap();
    assert!(owner_seen.reports.iter().all(|(r, _)| r.offset <= 9), "{tty:?}: its own count: {owner_seen:?}");
    drop((writer_seen, owner_seen));
    owner.echo_first(tty);
    writer.echo_first(tty);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_with_no_echo_is_reported_to_the_seat_that_typed_it() {
    // The line discipline always echoes: its shell cannot turn that off.
    for tty in Tty::here().into_iter().filter(|tty| tty.sized()) {
        no_echo_on(tty).await;
    }
}

async fn no_echo_on(tty: Tty) {
    let server = Server::on(tty);
    let (owner, writer, _silent, _watcher) = seats(&server, tty).await;
    owner.send(b"stty -echo; echo QUIET_$((6*7))_END; exec cat\r").await;
    writer.until("the shell's answer", |seen| seen.text().contains("QUIET_42_END")).await;
    // Past the owner's lease; then the keys make no output at all.
    tokio::time::sleep(Duration::from_millis(500)).await;
    writer.send(b"pw").await;
    writer.until("the report of pw", |seen| seen.report_of(2).is_some()).await;
    let seen = writer.seen.lock().unwrap();
    let (report, _) = seen.report_of(2).unwrap();
    assert!(report.flags.hidden(), "{tty:?}: a line with no echo: {seen:?}");
    assert!(!seen.text().contains("pw"), "{tty:?}: no echo: {seen:?}");
}
