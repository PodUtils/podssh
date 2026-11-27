//! A node stays reachable for months with no person (T-710, cfb's ask
//! A-S-03): 120 days on a paused clock, in one process, of the node's own
//! tasks (its renewal, its lines, its move to the next pair, the rotation of
//! its stop token) against the relay role's table of pairs with its file.
//!
//! The node's requests by the stop token reach the role's table in this
//! process (`ByStop::Here`), as `/v1/renew` and `/v1/rotate` answer them, and
//! the process's clock follows tokio's (`podssh_relay::clock`), so that each
//! sleep and each read of the clock move together. What the test plays:
//! the role renews none from day 1.5 (a relay of the contract), so the
//! first pair ends on day 3; the owner made the next pair on day 2.5, and
//! the role renews again; the node takes it at the expiry; the role restarts
//! from its file on day 60; every day the operator's file of the pair held
//! reaches the node, and a member of the net reaches it by the node's key
//! with no file at all. The sockets are not in it: the tests of the role
//! (`podssh-relay`) and `node_expiry` hold those.
#![cfg(unix)]

mod cleanup;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_cli::node_by_stop::{ByStop, Here};
use podssh_cli::node_expiry::{watch_by, Say};
use podssh_relay::identity::PublicKey;
use podssh_relay::pair::renew::Renewed;
use podssh_relay::pair::rotate::Rotated;
use podssh_relay::pair::{self, Pair, PairError};
use podssh_relay::relay::Relay;
use podssh_relay::reverse::control::Hello;
use podssh_relay::serve::reverse::outbox::Outbox;
use podssh_relay::serve::reverse::pairs::{Asker, Leg, Made, NodeLink, Pairs, Role};
use sha2::{Digest, Sha256};

const HOUR: u64 = 3_600_000;
const DAYS: u64 = 120;
const LABEL: &str = "months";

/// The hours of the test's events, from its start.
const OFF: u64 = 36; // day 1.5: the role renews and rotates none
const NEXT: u64 = 60; // day 2.5: the next pair is made and stored; the role renews again
const MOVE: u64 = 73; // day 3 and an hour: the first pair ended, the node's socket calls the hook
const RESTART: u64 = 60 * 24 + 20; // day 60 and 20 h: the role reads its file again

/// The process's clock now, as the role counts it.
fn now() -> u64 {
    u64::try_from(podssh_relay::clock::now_ms()).expect("after the epoch")
}

/// A relay role of this process: its table of pairs, read again from its
/// file at a restart, and whether it serves the renewal and the rotation.
struct InProcess {
    pairs: Mutex<Arc<Pairs>>,
    file: PathBuf,
    serves: AtomicBool,
}

impl InProcess {
    fn new(file: PathBuf) -> InProcess {
        let pairs = Arc::new(Pairs::open(Some(file.clone())).expect("a role's first run"));
        InProcess { pairs: Mutex::new(pairs), file, serves: AtomicBool::new(true) }
    }

    fn pairs(&self) -> Arc<Pairs> {
        self.pairs.lock().unwrap().clone()
    }

    fn restart(&self) {
        let again = Pairs::open(Some(self.file.clone())).expect("the role reads its file again");
        *self.pairs.lock().unwrap() = Arc::new(again);
    }

    /// The table, when `pair`'s stop token is the pair's: else the `403` of
    /// each failed authentication.
    fn by_stop(&self, pair: &Pair) -> Result<Arc<Pairs>, PairError> {
        let pairs = self.pairs();
        let found = pairs.find(&pair.name, Role::Stop, Some(pair.stop_token()), now());
        found.map(|_| pairs).ok_or_else(|| PairError::Forbidden { detail: String::new(), once: false })
    }
}

impl Here for InProcess {
    fn renew(&self, pair: &Pair) -> Result<Renewed, PairError> {
        // A relay of the contract has no such path: 404, before any token.
        if !self.serves.load(Ordering::SeqCst) {
            return Ok(Renewed::NotServed);
        }
        match self.by_stop(pair)?.renew(&pair.name, now()) {
            Ok(Some(until)) => Ok(Renewed::Until(i64::try_from(until).unwrap())),
            Ok(None) => Err(PairError::Forbidden { detail: String::new(), once: false }),
            Err(detail) => Err(PairError::NotIssued { detail }),
        }
    }

    fn rotate(&self, pair: &Pair, next: &str) -> Result<Rotated, PairError> {
        if !self.serves.load(Ordering::SeqCst) {
            return Ok(Rotated::NotServed);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(next.as_bytes()));
        match self.by_stop(pair)?.rotate(&pair.name, digest, now()) {
            Ok(Some(())) => Ok(Rotated::Asked),
            Ok(None) => Err(PairError::Forbidden { detail: String::new(), once: false }),
            Err(detail) => Err(PairError::NotIssued { detail }),
        }
    }
}

/// The pair as the node's store keeps it, from the role's answer.
fn node_pair(made: &Made) -> Pair {
    let body = serde_json::json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    let relay = Relay { host: "relay.test".into(), port: 443 };
    pair::parse(&relay, body.to_string().as_bytes(), podssh_relay::clock::now_ms()).expect("a pair of the role")
}

/// The node's socket joins `made` at the role, by its node token; its far
/// end is read and dropped, so that no write of the role waits.
fn join(pairs: &Pairs, made: &Made) {
    let pair = pairs.find(&made.name, Role::Node, Some(&made.node), now()).expect("the node's token is taken");
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), pairs.writers.clone());
    pair.lock().node = Some(NodeLink { serial: pairs.serial(), outbox: Some(outbox) });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut theirs, &mut tokio::io::sink()).await;
    });
}

/// A socket of the node's heard the role's `hello`, which offers the
/// rotation of the stop token.
fn heard() {
    let hello: Hello = serde_json::from_str(r#"{"maxSessions":64,"stopRotation":true}"#).unwrap();
    podssh_relay::reverse::legs::heard(&hello);
}

/// Whether the node of `held` is reachable now: its own token, the
/// operator's file of the pair (its connect token), and a member of the net
/// by the node's `key` with no file: a token of one leg, drawn and spent.
fn reachable(pairs: &Pairs, held: &Made, key: &PublicKey) -> Result<(), String> {
    let at = now();
    pairs.find(&held.name, Role::Node, Some(&held.node), at).ok_or("the role refused the node's token")?;
    pairs.find(&held.name, Role::Connect, Some(&held.connect), at).ok_or("the role refused the operator's file")?;
    let (name, token, _) = pairs.draw_leg(key, at).map_err(|e| format!("no leg for the member: {e:?}"))?;
    if name != held.name {
        return Err("the member's leg is of another pair".into());
    }
    let (pair, digest) = pairs.find_leg(&name, Some(&token), at).ok_or("the member's token was not found")?;
    match pairs.spend_leg(&pair, &digest, at) {
        Leg::Taken => Ok(()),
        other => Err(format!("the member's upgrade: {other:?}")),
    }
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-node-months-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).unwrap();
    podssh_relay::cache::private_dir(&dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

#[test]
fn a_node_stays_reachable_for_120_days_through_renewals_a_move_a_restart_and_rotations() {
    let home = scratch();
    // SAFETY: the one test of this binary sets it before it starts a thread;
    // the store of the node's pairs is this test's, never the user's.
    unsafe { std::env::set_var("PODSSH_CACHE_DIR", home.join("cache")) };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
    let lines = runtime.block_on(months(&home));
    let count = |words: &str| lines.iter().filter(|line| line.contains(words)).count();
    let all = lines.join("\n");
    // The next pair is renewed each 48 h from day 4.5: 58 times to day 120.
    assert!(count("the pair is renewed at its relay until") >= 57, "{all}");
    // Each day, its stop token: the first pair's twice, the next one's 117 times.
    assert!(count("the pair's stop token is new at its relay") >= 115, "{all}");
    assert_eq!(count("the pair expired; the next pair under"), 1, "{all}");
    assert_eq!(count("did not take") + count("refused") + count("was not rotated"), 0, "{all}");
    // What `podssh status` reads as `renews` (T-710): the pair now renews.
    let kept = podssh_relay::cache::load_file(&format!("renews-{LABEL}.json")).expect("the node's record");
    let kept: serde_json::Value = serde_json::from_str(&kept).unwrap();
    assert_eq!(kept["renews"], true, "{kept}");
}

/// The 120 days; the lines that the node said.
async fn months(home: &Path) -> Vec<String> {
    let _clock = podssh_relay::clock::follow_tokio(podssh_relay::clock::wall_ms());
    let start = tokio::time::Instant::now();
    let role = Arc::new(InProcess::new(home.join("pairs.json")));
    let member = PublicKey([7; 32]);
    // The node's key made its pairs here, so that a member's leg finds them.
    let asker = Asker { key: member.fingerprint(), keys: 1 };
    let first = role.pairs().make_for(now(), false, Some(&asker)).expect("the first pair");
    pair::store(LABEL, &node_pair(&first)).expect("the store takes the pair");
    join(&role.pairs(), &first);

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let say: Say = {
        let lines = lines.clone();
        Arc::new(move |line| lines.lock().unwrap().push(line))
    };
    let (hook, task) = watch_by(LABEL, &node_pair(&first), true, say, ByStop::Here(role.clone()));
    let hook = hook.expect("a pair of the store has the hook of its expiry");
    heard();

    let mut held = first;
    let mut next: Option<Made> = None;
    for hour in 1..=DAYS * 24 {
        tokio::time::sleep_until(start + Duration::from_millis(hour * HOUR)).await;
        match hour {
            OFF => role.serves.store(false, Ordering::SeqCst),
            NEXT => {
                // `podssh relay pair LABEL`, in the first pair's last day.
                let made = role.pairs().make_for(now(), false, Some(&asker)).expect("the next pair");
                pair::store(LABEL, &node_pair(&made)).expect("the store takes the next pair");
                role.serves.store(true, Ordering::SeqCst);
                next = Some(made);
            }
            MOVE => {
                let made = next.take().expect("the next pair was made");
                let took = hook().await.expect("the node takes the next pair");
                assert_eq!(took.name, made.name, "the pair stored under the label");
                join(&role.pairs(), &made);
                // The next pair's own socket heard the offer: its rotation begins.
                heard();
                held = made;
            }
            RESTART => {
                role.restart();
                join(&role.pairs(), &held);
            }
            _ => {}
        }
        // Each day, two hours in: clear of the events above.
        if hour % 24 == 2 {
            if let Err(why) = reachable(&role.pairs(), &held, &member) {
                task.abort();
                let said = lines.lock().unwrap().join("\n");
                panic!("day {}: {why}\nthe node said:\n{said}", hour / 24);
            }
        }
    }
    task.abort();
    let said = lines.lock().unwrap();
    said.clone()
}
