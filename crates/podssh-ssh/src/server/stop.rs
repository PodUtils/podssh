//! The life of `podssh serve` (T-117): a clean stop, and the authorized keys
//! read again while it serves.
//!
//! A stop takes no new session, tells each client why with a disconnect,
//! and hangs up each child's process group (SIGHUP, then SIGCONT, as the
//! kernel does for a terminal that goes away); a group that still runs
//! after [`GRACE`] is killed, and a second stop kills at once. So a node
//! that stops leaves no shell behind, and cuts no session with no word.
//!
//! The keys are one set shared by each connection of the server, each line
//! with its rules (T-114), replaced whole by a reload: a new login is
//! checked against the set of the moment, and a session that logged in
//! goes on under the rules it logged in with, which its handler holds.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use russh::keys::PublicKey;
use russh::server::Handle;
use russh::Disconnect;
use tokio::sync::watch;

use super::authorized::Admission;
use super::rules::Context;
use super::Authorized;

/// How long a stop waits for each child to end after its hangup, before it
/// kills what is left.
pub const GRACE: Duration = Duration::from_secs(5);

/// The reason of the disconnect that a stop sends: OpenSSH prints it
/// (`Received disconnect from ...: podssh serve is stopping`).
pub const STOPPING: &str = "podssh serve is stopping";

/// How long the disconnect may wait for the session's queue: a client that
/// reads nothing holds it, and the stop does not wait on such a client.
const SAY_LIMIT: Duration = Duration::from_secs(1);

/// How often a stop looks whether each child ended.
const TICK: Duration = Duration::from_millis(50);

/// The keys that may log in, shared by each connection of one server and
/// replaced whole by a reload.
#[derive(Debug, Clone)]
pub struct Keys(Arc<RwLock<Arc<Authorized>>>);

impl Keys {
    pub fn new(authorized: Authorized) -> Keys {
        Keys(Arc::new(RwLock::new(Arc::new(authorized))))
    }

    /// The set of this moment.
    pub fn current(&self) -> Arc<Authorized> {
        // A writer that panicked left a whole set: the swap is one store.
        match self.0.read() {
            Ok(set) => set.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Put `authorized` in the place of the set, whole. An empty set is
    /// refused (`false`): no reload leaves a server that nobody can log in
    /// to, nor one that a later check takes for open.
    pub fn replace(&self, authorized: Authorized) -> bool {
        if authorized.is_empty() {
            return false;
        }
        let new = Arc::new(authorized);
        match self.0.write() {
            Ok(mut set) => *set = new,
            Err(poisoned) => *poisoned.into_inner() = new,
        }
        true
    }

    /// Whether `key` may log in under `at`, and with which rules, in the
    /// set of this moment (T-114's `Authorized::admit`).
    pub fn admit(&self, key: &PublicKey, at: &Context) -> Admission {
        self.current().admit(key, at)
    }

    /// Whether `key` may log in now, from no known address.
    pub fn allows(&self, key: &PublicKey) -> bool {
        self.current().allows(key)
    }

    pub fn is_empty(&self) -> bool {
        self.current().is_empty()
    }

    pub fn len(&self) -> usize {
        self.current().len()
    }
}

impl From<Arc<Authorized>> for Keys {
    fn from(authorized: Arc<Authorized>) -> Keys {
        Keys(Arc::new(RwLock::new(authorized)))
    }
}

/// Where a server is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Serving,
    /// Asked to stop: no new session, each child hung up.
    Stopping,
    /// Asked again, or past [`GRACE`]: each child left is killed.
    Killing,
}

/// The process groups of the children that run, as each channel's slot.
#[derive(Debug, Clone, Default)]
pub(super) struct Groups(Arc<Mutex<Vec<Weak<AtomicI32>>>>);

impl Groups {
    /// A new slot for one channel's group (0 while none runs), kept until
    /// the channel drops it.
    pub(super) fn slot(&self) -> Arc<AtomicI32> {
        let slot = Arc::new(AtomicI32::new(0));
        let mut all = self.0.lock().unwrap_or_else(|p| p.into_inner());
        all.retain(|weak| weak.strong_count() > 0);
        all.push(Arc::downgrade(&slot));
        slot
    }

    /// The groups whose leader runs now.
    pub(super) fn running(&self) -> Vec<i32> {
        let all = self.0.lock().unwrap_or_else(|p| p.into_inner());
        all.iter().filter_map(Weak::upgrade).map(|slot| slot.load(Ordering::SeqCst)).filter(|g| *g > 0).collect()
    }

    /// Send `signals` to each group that runs; how many groups were there.
    pub(super) fn signal(&self, signals: &[i32]) -> usize {
        let groups = self.running();
        for group in &groups {
            for signal in signals {
                to_group(*group, *signal);
            }
        }
        groups.len()
    }
}

/// `signal` to the process group `group`; a group that ended is no error.
pub(super) fn to_group(group: i32, signal: i32) {
    #[cfg(unix)]
    if group > 0 {
        // SAFETY: kill has no memory effect; a group gone gives ESRCH.
        unsafe {
            libc::kill(-group, signal);
        }
    }
    #[cfg(not(unix))]
    let _ = (group, signal);
}

/// The hangup of a group: SIGHUP, then SIGCONT so that a stopped job
/// hears it, as the kernel sends both when a terminal goes away.
#[cfg(unix)]
pub(super) const HANGUP: &[i32] = &[libc::SIGHUP, libc::SIGCONT];
#[cfg(not(unix))]
pub(super) const HANGUP: &[i32] = &[];

#[cfg(unix)]
const KILL: &[i32] = &[libc::SIGKILL];
#[cfg(not(unix))]
const KILL: &[i32] = &[];

/// What the caller holds to stop a server, shared by each of its
/// connections: [`Control::stop`] on SIGTERM and SIGINT.
#[derive(Debug, Clone)]
pub struct Control {
    stage: Arc<watch::Sender<Stage>>,
    pub(super) groups: Groups,
}

impl Default for Control {
    fn default() -> Self {
        Control::new()
    }
}

impl Control {
    pub fn new() -> Control {
        let (stage, _) = watch::channel(Stage::Serving);
        Control { stage: Arc::new(stage), groups: Groups::default() }
    }

    /// Ask the server to stop; asked again, it kills each child at once.
    pub fn stop(&self) {
        self.stage.send_modify(|stage| {
            *stage = match *stage {
                Stage::Serving => Stage::Stopping,
                _ => Stage::Killing,
            }
        });
    }

    pub fn stage(&self) -> Stage {
        *self.stage.borrow()
    }

    /// How many children run now, in all the connections.
    pub fn children(&self) -> usize {
        self.groups.running().len()
    }

    pub(super) fn watch(&self) -> watch::Receiver<Stage> {
        self.stage.subscribe()
    }
}

/// Wait until the stage is `at` or past it. A sender gone never comes: the
/// caller's own control holds it.
pub(super) async fn reached(stage: &mut watch::Receiver<Stage>, at: Stage) {
    let _ = stage.wait_for(|now| *now >= at).await;
}

/// The stop of one connection: the disconnect with its reason, the hangup
/// of each child, then the wait for each child and for the session, within
/// [`GRACE`] or until a second stop; then each child left is killed.
pub(super) async fn wind_down<F>(handle: Handle, control: &Control, session: F)
where
    F: std::future::Future + Send,
{
    // The disconnect waits on the session's queue; it is said on a task of
    // its own, so a client that reads nothing holds no part of the stop.
    tokio::spawn(async move {
        let said = handle.disconnect(Disconnect::ByApplication, STOPPING.into(), String::new());
        let _ = tokio::time::timeout(SAY_LIMIT, said).await;
    });
    control.groups.signal(HANGUP);
    let mut stage = control.watch();
    let deadline = tokio::time::Instant::now() + GRACE;
    tokio::pin!(session);
    let mut ended = false;
    loop {
        if ended && control.groups.running().is_empty() {
            return;
        }
        tokio::select! {
            _ = &mut session, if !ended => ended = true,
            () = reached(&mut stage, Stage::Killing) => break,
            () = tokio::time::sleep_until(deadline) => break,
            () = tokio::time::sleep(TICK) => {}
        }
    }
    control.groups.signal(KILL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_stop_kills_and_a_third_stays_there() {
        let control = Control::new();
        assert_eq!(control.stage(), Stage::Serving);
        control.stop();
        assert_eq!(control.stage(), Stage::Stopping);
        control.stop();
        assert_eq!(control.stage(), Stage::Killing);
        control.stop();
        assert_eq!(control.stage(), Stage::Killing);
    }

    #[test]
    fn a_group_counts_while_its_slot_holds_a_leader_and_leaves_with_the_slot() {
        let groups = Groups::default();
        let (a, b) = (groups.slot(), groups.slot());
        assert!(groups.running().is_empty());
        a.store(4242, Ordering::SeqCst);
        assert_eq!(groups.running(), vec![4242]);
        b.store(4343, Ordering::SeqCst);
        drop(a);
        assert_eq!(groups.running(), vec![4343], "a dropped slot is no group");
        b.store(0, Ordering::SeqCst);
        assert!(groups.running().is_empty());
    }

    #[test]
    fn a_reload_replaces_the_set_whole_and_never_with_an_empty_one() {
        let one = crate::keygen::generate(crate::keygen::KeyKind::Ed25519, "one").unwrap();
        let two = crate::keygen::generate(crate::keygen::KeyKind::Ed25519, "two").unwrap();
        let mut first = Authorized::new();
        first.add(one.public_key().key_data().clone());
        let keys = Keys::new(first);
        let shared = keys.clone();
        assert!(shared.allows(one.public_key()) && !shared.allows(two.public_key()));
        let mut second = Authorized::new();
        second.add(two.public_key().key_data().clone());
        assert!(keys.replace(second));
        assert!(!shared.allows(one.public_key()), "a key that the new set lacks is out");
        assert!(shared.allows(two.public_key()));
        assert!(!keys.replace(Authorized::new()), "an empty set is refused");
        assert!(shared.allows(two.public_key()), "and the set before stays");
    }
}
