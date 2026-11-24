//! The lines of one connection of the audit log (T-116): [`Trail`] says
//! the connection, its logins and its refusals; [`Session`] says a session
//! channel's start and, when it is dropped, its end with the counts of its
//! [`Tally`]; [`Forward`] says a forward's open, its refusal, or its end.
//! With no `--audit-log`, each is empty and says nothing.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Instant;

use serde_json::{Map, Value};
use tokio::io::AsyncWrite;

use super::{bounded, Audit, Level, MOST_COMMAND, MOST_TEXT};
use crate::server::Settings;

/// How a session's program ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    Status(u32),
    Signal(String),
}

/// The counts of one channel, kept whether or not a log is written: the
/// bytes that the client sent on it and that serve sent back, and how its
/// program ended.
#[derive(Debug, Default)]
pub struct Tally {
    took: AtomicU64,
    gave: AtomicU64,
    exit: Mutex<Option<Exit>>,
}

impl Tally {
    /// `n` bytes from the client.
    pub fn took(&self, n: usize) {
        self.took.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// `n` bytes to the client.
    pub fn gave(&self, n: usize) {
        self.gave.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// The program's end, as its exit-status or exit-signal said it.
    pub fn exited(&self, exit: Exit) {
        *self.exit.lock().unwrap_or_else(PoisonError::into_inner) = Some(exit);
    }

    fn ended(&self) -> Option<Exit> {
        self.exit.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// `to`, counting each byte that it takes as given to the client.
    pub fn count<W>(self: &Arc<Self>, to: W) -> Counted<W> {
        Counted { to, tally: self.clone() }
    }
}

/// A writer to the client that counts what it takes.
pub struct Counted<W> {
    to: W,
    tally: Arc<Tally>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Counted<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.to).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            self.tally.gave(n);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.to).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.to).poll_shutdown(cx)
    }
}

/// What a session channel asked for.
#[derive(Debug, Clone, Copy)]
pub enum Asked<'a> {
    Shell,
    Exec(&'a [u8]),
    Subsystem(&'a str),
}

impl Asked<'_> {
    fn name(&self) -> &'static str {
        match self {
            Asked::Shell => "shell",
            Asked::Exec(_) => "exec",
            Asked::Subsystem(_) => "subsystem",
        }
    }
}

/// Whether a login was let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// A key that passed, with the one-time code still to come (T-115).
    Partial,
    Refused,
}

/// The log of one connection; empty without `--audit-log`.
pub struct Trail {
    inner: Option<Inner>,
}

struct Inner {
    audit: Arc<Audit>,
    conn: String,
    since: Instant,
    /// False with `--share`, where a login name can be a shell's name,
    /// which is the right to that shell: it is never written.
    users: bool,
}

impl Trail {
    /// The trail of a new connection, with its `serve.conn.open` line.
    pub fn open(settings: &Settings) -> Trail {
        let Some(audit) = settings.audit.clone() else { return Trail { inner: None } };
        let inner = Inner { conn: audit.conn_id(), audit, since: Instant::now(), users: !settings.share };
        let peer = settings.peer.map_or(Value::Null, |ip| Value::from(ip.to_string()));
        inner.audit.line("serve.conn.open", Level::Info, inner.fields(&[("peer", peer)]));
        Trail { inner: Some(inner) }
    }

    /// A trail that writes nothing.
    pub fn none() -> Trail {
        Trail { inner: None }
    }

    /// A login of `user` by `method`, with the key's fingerprint where one
    /// was shown, and why it was refused.
    pub fn auth(&self, verdict: Verdict, user: &str, key: Option<&str>, method: &str, why: Option<&str>) {
        let Some(inner) = &self.inner else { return };
        let (event, level) = match verdict {
            Verdict::Accepted => ("serve.auth.accepted", Level::Info),
            Verdict::Partial => ("serve.auth.partial", Level::Info),
            Verdict::Refused => ("serve.auth.refused", Level::Warn),
        };
        let mut fields = inner.fields(&[("method", Value::from(method))]);
        if inner.users {
            fields.insert("user".into(), Value::from(bounded(user, MOST_TEXT).0));
        }
        fields.insert("key".into(), key.map_or(Value::Null, Value::from));
        if let Some(why) = why {
            fields.insert("reason".into(), Value::from(bounded(why, MOST_TEXT).0));
        }
        inner.audit.line(event, level, fields);
    }

    /// A session that starts on `channel`: its `serve.session.start` line,
    /// and the mark whose drop writes its end. `ran` is the command that
    /// runs where a key's `command=` replaced the client's.
    pub fn session(
        &self,
        at: Place<'_>,
        asked: Asked<'_>,
        ran: Option<&[u8]>,
        pty: bool,
        tally: Arc<Tally>,
    ) -> Option<Session> {
        let inner = self.inner.as_ref()?;
        let mut fields = at.fields(inner);
        fields.insert("request".into(), Value::from(asked.name()));
        fields.insert("pty".into(), Value::from(pty));
        fields.insert("forced".into(), Value::from(ran.is_some()));
        if let Asked::Subsystem(name) = asked {
            fields.insert("subsystem".into(), Value::from(bounded(name, MOST_TEXT).0));
        }
        if inner.audit.commands() {
            let own = match asked {
                Asked::Exec(command) => Some(command),
                _ => None,
            };
            if let Some(command) = ran.or(own) {
                insert_command(&mut fields, "command", command);
            }
            if let (Some(_), Some(original)) = (ran, own) {
                insert_command(&mut fields, "original", original);
            }
        }
        inner.audit.line("serve.session.start", Level::Info, fields);
        let base = at.fields(inner);
        Some(Session { audit: inner.audit.clone(), base, tally, since: Instant::now() })
    }

    /// A session request refused on its channel, and why.
    pub fn session_refused(&self, at: Place<'_>, asked: Asked<'_>, why: &str) {
        let Some(inner) = &self.inner else { return };
        let mut fields = at.fields(inner);
        fields.insert("request".into(), Value::from(asked.name()));
        fields.insert("reason".into(), Value::from(bounded(why, MOST_TEXT).0));
        inner.audit.line("serve.session.refused", Level::Warn, fields);
    }

    /// A forward to `host:port` asked by `key`: the mark that says its
    /// open or its refusal, then its end.
    pub fn forward(&self, key: &str, host: &str, port: u32) -> Option<Forward> {
        let inner = self.inner.as_ref()?;
        let fields = inner.fields(&[("key", Value::from(key)), ("target", target(host, port))]);
        Some(Forward { audit: inner.audit.clone(), base: fields, tally: Arc::default(), opened: None })
    }

    /// A forward refused before its dial, and why.
    pub fn forward_refused(&self, key: &str, host: &str, port: u32, why: &str) {
        if let Some(mut forward) = self.forward(key, host, port) {
            forward.refused(why);
        }
    }
}

impl Drop for Trail {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            let fields = inner.fields(&[("duration_ms", millis(inner.since))]);
            inner.audit.line("serve.conn.close", Level::Info, fields);
        }
    }
}

impl Inner {
    fn fields(&self, pairs: &[(&str, Value)]) -> Map<String, Value> {
        let mut fields = Map::new();
        fields.insert("conn".into(), Value::from(self.conn.as_str()));
        for (k, v) in pairs {
            fields.insert((*k).to_string(), v.clone());
        }
        fields
    }
}

/// A channel of a key that logged in.
#[derive(Debug, Clone, Copy)]
pub struct Place<'a> {
    pub channel: u32,
    pub key: &'a str,
}

impl Place<'_> {
    fn fields(&self, inner: &Inner) -> Map<String, Value> {
        inner.fields(&[("channel", Value::from(self.channel)), ("key", Value::from(self.key))])
    }
}

/// A session that runs; its drop writes `serve.session.end`.
pub struct Session {
    audit: Arc<Audit>,
    base: Map<String, Value>,
    tally: Arc<Tally>,
    since: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut fields = self.base.clone();
        match self.tally.ended() {
            Some(Exit::Status(code)) => fields.insert("exit_status".into(), Value::from(code)),
            Some(Exit::Signal(name)) => fields.insert("exit_signal".into(), Value::from(name)),
            // The client closed the channel, or the connection ended,
            // before the program did.
            None => fields.insert("ended".into(), Value::from("closed before an exit")),
        };
        fields.insert("bytes_in".into(), Value::from(self.tally.took.load(Ordering::Relaxed)));
        fields.insert("bytes_out".into(), Value::from(self.tally.gave.load(Ordering::Relaxed)));
        fields.insert("duration_ms".into(), millis(self.since));
        self.audit.line("serve.session.end", Level::Info, fields);
    }
}

/// A forward: its open or its refusal, then, once opened, its end.
pub struct Forward {
    audit: Arc<Audit>,
    base: Map<String, Value>,
    tally: Arc<Tally>,
    opened: Option<Instant>,
}

impl Forward {
    /// The counts of its bytes.
    pub fn tally(&self) -> Arc<Tally> {
        self.tally.clone()
    }

    /// The dial took: `serve.forward.open`.
    pub fn opened(&mut self) {
        self.opened = Some(Instant::now());
        self.audit.line("serve.forward.open", Level::Info, self.base.clone());
    }

    /// Refused, by a rule or by its dial: `serve.forward.refused`, and no
    /// end follows.
    pub fn refused(&mut self, why: &str) {
        self.opened = None;
        let mut fields = self.base.clone();
        fields.insert("reason".into(), Value::from(bounded(why, MOST_TEXT).0));
        self.audit.line("serve.forward.refused", Level::Warn, fields);
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        let Some(since) = self.opened else { return };
        let mut fields = self.base.clone();
        fields.insert("bytes_in".into(), Value::from(self.tally.took.load(Ordering::Relaxed)));
        fields.insert("bytes_out".into(), Value::from(self.tally.gave.load(Ordering::Relaxed)));
        fields.insert("duration_ms".into(), millis(since));
        self.audit.line("serve.forward.close", Level::Info, fields);
    }
}

/// `host:port`, the host bounded; an IPv6 address in brackets.
fn target(host: &str, port: u32) -> Value {
    let host = bounded(host, MOST_TEXT).0;
    Value::from(if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") })
}

/// A command line in `fields`, bounded, with `KEY_cut` when it was cut;
/// bytes that are not UTF-8 are replaced, as JSON holds text alone.
fn insert_command(fields: &mut Map<String, Value>, key: &str, command: &[u8]) {
    let (text, cut) = bounded(&String::from_utf8_lossy(command), MOST_COMMAND);
    fields.insert(key.to_string(), Value::from(text));
    if cut {
        fields.insert(format!("{key}_cut"), Value::from(true));
    }
}

fn millis(since: Instant) -> Value {
    Value::from(u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX))
}
