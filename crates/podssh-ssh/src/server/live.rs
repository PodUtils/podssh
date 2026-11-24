//! The live connections of a server (T-842): the key that logged in on
//! each, its children's process groups, and a way to end it alone.
//!
//! A reload replaces the keys whole and leaves each session that logged in
//! under the rules it got (T-117). With `--revoke-ends-sessions`, the
//! reload also ends each connection whose key the new set no longer lets
//! in: a disconnect that names the key, then the hangup of its children,
//! as a stop ends each connection; a key whose `expiry-time=` passes ends
//! its sessions at that second the same way. Without the flag, nothing of
//! this ends a session.
//!
//! The same table holds the names of the shared shells (T-837,
//! `share.rs`): a login under a name is a connection here with no key, so
//! no reload ends it; its name, and its shell's end, do.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use russh::keys::PublicKey;
use tokio::sync::watch;

use super::authorized::{Admission, Authorized};
use super::rules::Context;
use super::stop::{Control, Groups, Keys};
use super::Settings;

/// The longest sleep of an expiry's timer: past it the time is read again,
/// so a far date or a clock that was set meets no overflow and no drift.
const LONGEST_WAIT: u64 = 24 * 60 * 60;

/// One connection that a reload ended: the key's fingerprint, and why, in
/// words for the operator's line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub who: String,
    pub why: String,
}

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "key {}: {}: its session ends", self.who, self.why)
    }
}

/// What a reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reloaded {
    /// The new set is in force; the connections that it ended, none
    /// without `--revoke-ends-sessions`.
    Taken(Vec<Ended>),
    /// The new set had no key: the set before stays, and nothing ends.
    Refused,
}

/// Put `set` in the place of the keys, whole (T-117); with `ends`, end each
/// connection whose key the new set does not let in now (T-842). An empty
/// set is refused, and then nothing ends.
pub fn reload(keys: &Keys, control: &Control, set: Authorized, ends: bool) -> Reloaded {
    if !keys.replace(set) {
        return Reloaded::Refused;
    }
    if !ends {
        return Reloaded::Taken(Vec::new());
    }
    Reloaded::Taken(control.live.revoke(&keys.current()))
}

#[derive(Debug)]
struct State {
    /// The key of the login and its fingerprint; None before a login.
    who: Mutex<Option<(PublicKey, String)>>,
    /// A login was accepted, by a key or by a shared shell's name: the
    /// client's close of the stream after it is its end (T-869).
    accepted: AtomicBool,
    /// The client's address, for the `from=` of the new set.
    peer: Option<IpAddr>,
    /// This connection's children, beside the server's list of them all.
    groups: Groups,
    /// What the client is told when this connection is ended; None while
    /// it lives.
    ended: watch::Sender<Option<String>>,
}

/// One connection, as its handler and the server's table hold it.
#[derive(Debug, Clone)]
pub(super) struct Conn(Arc<State>);

impl Conn {
    /// `key` logs in, or tries to: set before the key is checked, so that a
    /// reload between the check and this line cannot miss the connection.
    pub(super) fn log_in(&self, key: &PublicKey) {
        let who = Some((key.clone(), crate::known_hosts::fingerprint(key)));
        *self.0.who.lock().unwrap_or_else(|p| p.into_inner()) = who;
    }

    /// A login was accepted on this connection, by a key or by a name.
    pub(super) fn accept(&self) {
        self.0.accepted.store(true, Ordering::Relaxed);
    }

    /// Whether a login was accepted on this connection.
    pub(super) fn accepted(&self) -> bool {
        self.0.accepted.load(Ordering::Relaxed)
    }

    /// The key was refused: no login to end.
    pub(super) fn log_out(&self) {
        *self.0.who.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub(super) fn groups(&self) -> &Groups {
        &self.0.groups
    }

    /// What the client was told, once the connection was ended.
    pub(super) fn ended(&self) -> Option<String> {
        self.0.ended.borrow().clone()
    }

    /// End the connection, telling the client `told`; false when it was
    /// ended before, whose first words stand.
    pub(super) fn end(&self, told: String) -> bool {
        self.0.ended.send_if_modified(|now| {
            if now.is_some() {
                return false;
            }
            *now = Some(told);
            true
        })
    }

    pub(super) fn watch(&self) -> watch::Receiver<Option<String>> {
        self.0.ended.subscribe()
    }
}

/// Wait until the connection is ended; what the client is told. The sender
/// lives in the connection that waits, so it never goes first.
pub(super) async fn ended(watch: &mut watch::Receiver<Option<String>>) -> String {
    // The guard of `wait_for` is dropped before any other await: a held
    // guard would make the connection's future not Send.
    let told = watch.wait_for(Option::is_some).await.map(|told| told.clone().unwrap_or_default());
    match told {
        Ok(told) => told,
        Err(_) => std::future::pending().await,
    }
}

/// The live connections of one server, shared by each of them, and the
/// names of its shared shells.
#[derive(Debug, Clone, Default)]
pub(super) struct Live {
    conns: Arc<Mutex<Vec<Weak<State>>>>,
    pub(super) shares: super::share::Shares,
}

impl Live {
    /// A new connection from `peer`, kept until the last of its holders
    /// drops it.
    pub(super) fn join(&self, peer: Option<IpAddr>) -> Conn {
        let (ended, _) = watch::channel(None);
        let state = Arc::new(State {
            who: Mutex::new(None),
            accepted: AtomicBool::new(false),
            peer,
            groups: Groups::default(),
            ended,
        });
        let mut all = self.conns.lock().unwrap_or_else(|p| p.into_inner());
        all.retain(|weak| weak.strong_count() > 0);
        all.push(Arc::downgrade(&state));
        Conn(state)
    }

    fn each(&self) -> Vec<Conn> {
        let all = self.conns.lock().unwrap_or_else(|p| p.into_inner());
        all.iter().filter_map(Weak::upgrade).map(Conn).collect()
    }

    /// How many connections have a key logged in now.
    pub(super) fn logged_in(&self) -> usize {
        self.each().iter().filter(|c| c.0.who.lock().unwrap_or_else(|p| p.into_inner()).is_some()).count()
    }

    /// End each connection whose key `set` does not let in now, from its
    /// own address; each one ended, once.
    pub(super) fn revoke(&self, set: &Authorized) -> Vec<Ended> {
        let mut out = Vec::new();
        for conn in self.each() {
            let who = conn.0.who.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let Some((key, fingerprint)) = who else { continue };
            let why = match set.admit(&key, &Context::now(conn.0.peer)) {
                Admission::Admitted(_) => continue,
                Admission::Unlisted => "removed from the authorized keys".to_string(),
                Admission::Refused(reasons) => format!("refused by the authorized keys now: {}", reasons.join("; ")),
            };
            // The client hears that the key is out, not the operator's files.
            if conn.end(format!("podssh serve: the key {fingerprint} is no longer authorized")) {
                out.push(Ended { who: fingerprint, why });
            }
        }
        out
    }
}

/// End `conn` when the `expiry-time=` of its key, `expiry` (seconds since
/// 1970), has passed, with a line for the operator. The caller aborts the
/// timer when the connection ends first.
pub(super) fn end_at_expiry(conn: &Conn, expiry: i64, settings: Arc<Settings>) -> tokio::task::AbortHandle {
    let weak = Arc::downgrade(&conn.0);
    let task = tokio::spawn(async move {
        // Admitted while `expiry` is not past, so the end is the next second.
        loop {
            let now = Context::now(None).now;
            if now > expiry {
                break;
            }
            let left = u64::try_from(expiry.saturating_sub(now).saturating_add(1)).unwrap_or(1);
            tokio::time::sleep(Duration::from_secs(left.clamp(1, LONGEST_WAIT))).await;
        }
        let Some(state) = weak.upgrade() else { return };
        let conn = Conn(state);
        let who = conn.0.who.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|(_, f)| f.clone());
        let Some(who) = who else { return };
        let at = crate::sshsig::format_time(expiry);
        if conn.end(format!("podssh serve: the key {who} expired at {at}")) {
            settings.say(&Ended { who, why: format!("expiry-time: the key expired at {at}") }.to_string());
        }
    });
    task.abort_handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> russh::keys::PrivateKey {
        crate::keygen::generate(crate::keygen::KeyKind::Ed25519, "t").unwrap()
    }

    fn only(key: &russh::keys::PrivateKey) -> Authorized {
        let mut set = Authorized::new();
        set.add(key.public_key().key_data().clone());
        set
    }

    #[test]
    fn a_reload_ends_the_connection_of_a_removed_key_alone_and_only_when_asked() {
        let (one, two) = (key(), key());
        let mut both = only(&one);
        both.add(two.public_key().key_data().clone());
        let keys = Keys::new(both);
        let control = Control::new();
        let (a, b, waiting) = (control.live.join(None), control.live.join(None), control.live.join(None));
        a.log_in(one.public_key());
        b.log_in(two.public_key());
        assert_eq!(control.live.logged_in(), 2, "a connection with no login yet is not counted");

        assert_eq!(reload(&keys, &control, only(&two), false), Reloaded::Taken(Vec::new()));
        assert!(a.ended().is_none(), "without the flag, nothing ends");

        let ended = match reload(&keys, &control, only(&two), true) {
            Reloaded::Taken(ended) => ended,
            Reloaded::Refused => panic!("a set with a key is taken"),
        };
        let who = crate::known_hosts::fingerprint(one.public_key());
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert_eq!(ended[0].who, who);
        assert!(ended[0].to_string().contains("removed"), "{}", ended[0]);
        assert!(a.ended().is_some_and(|told| told.contains(&who)), "the client hears which key");
        assert!(b.ended().is_none() && waiting.ended().is_none(), "the other key, and no login, go on");

        // Ended once: a second reload names it no more.
        assert_eq!(reload(&keys, &control, only(&two), true), Reloaded::Taken(Vec::new()));
        assert_eq!(reload(&keys, &control, Authorized::new(), true), Reloaded::Refused);
        assert!(b.ended().is_none(), "a set with no key ends nothing");
    }

    #[test]
    fn a_refused_key_logs_out_and_a_dropped_connection_leaves_the_table() {
        let one = key();
        let control = Control::new();
        let a = control.live.join(None);
        a.log_in(one.public_key());
        a.log_out();
        assert_eq!(control.live.logged_in(), 0);
        a.log_in(one.public_key());
        drop(a);
        assert_eq!(control.live.logged_in(), 0, "a connection that ended is out of the table");
    }
}
