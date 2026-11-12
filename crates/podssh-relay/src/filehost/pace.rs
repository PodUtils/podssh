//! The bounds of the road (T-738's step 3): one outbound connection of the
//! road at a time, through `HTTPS_PROXY` as each of podssh's ([`Gate`]),
//! and an upload rate under each host's published one ([`every`], [`Hosts`]).
//! A host that refuses (429, or a failure) rests, and the next host in
//! order takes the piece: so a host that is busy for one user never stops
//! the session while another answers.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::time::Instant;

use super::host::Host;

/// The share of a host's published rate that the road uses: four fifths,
/// so that a retry, or a second session of the same user, stays under it.
const SHARE_NUM: u64 = 4;
const SHARE_DEN: u64 = 5;
/// The time between two uploads to a host that publishes no rate: the road
/// asks little of a volunteer's service whose limit it cannot read.
pub const UNPUBLISHED_EVERY: Duration = Duration::from_secs(30);
/// No host gets two uploads closer than this, whatever its rate.
pub const LEAST_EVERY: Duration = Duration::from_secs(5);
/// How long a host rests after a 429 that names no time, or a failure.
pub const REST: Duration = Duration::from_secs(10 * 60);

/// The time between two uploads to a host that publishes `per_hour`.
pub fn every(per_hour: Option<u32>) -> Duration {
    match per_hour {
        Some(rate) if rate > 0 => {
            let allowed = (u64::from(rate) * SHARE_NUM / SHARE_DEN).max(1);
            Duration::from_secs(3600u64.div_ceil(allowed)).max(LEAST_EVERY)
        }
        _ => UNPUBLISHED_EVERY,
    }
}

/// The road's one connection: each request of the road, to a host or to
/// the board, is made while it holds this, so both ways of a link and each
/// link of a process take turns (rule 2 of AGENTS.md, which names no
/// exception for this road).
#[derive(Clone, Default)]
pub struct Gate(Arc<Mutex<()>>);

impl Gate {
    pub async fn hold(&self) -> OwnedMutexGuard<()> {
        self.0.clone().lock_owned().await
    }
}

struct Slot {
    host: Arc<dyn Host>,
    every: Duration,
    /// When it may take its next upload.
    next: Instant,
    /// Until when it rests, after a refusal.
    rests: Option<Instant>,
}

/// The hosts of a road in their order, and when each may take an upload.
pub struct Hosts {
    slots: Vec<Slot>,
    /// The host that took the last upload: the next goes there too, until
    /// it refuses.
    at: usize,
}

impl Hosts {
    pub fn new(hosts: Vec<Arc<dyn Host>>, now: Instant) -> Hosts {
        let slots = hosts
            .into_iter()
            .map(|host| Slot { every: every(host.per_hour()), host, next: now, rests: None })
            .collect();
        Hosts { slots, at: 0 }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The host that takes the next upload of `size` bytes, and when: the
    /// first one from the last that took one that does not rest and takes
    /// that size; if each rests, the one whose rest ends first. `None` when
    /// no host takes that size.
    pub fn pick(&self, size: usize, now: Instant) -> Option<(usize, Instant)> {
        let count = self.slots.len();
        let fits = |i: &usize| self.slots[*i].host.most() >= size;
        let order = (0..count).map(|k| (self.at + k) % count).filter(fits);
        let mut soonest: Option<(usize, Instant)> = None;
        for i in order {
            let slot = &self.slots[i];
            match slot.rests {
                Some(until) if until > now => {
                    let when = until.max(slot.next);
                    if soonest.is_none_or(|(_, best)| when < best) {
                        soonest = Some((i, when));
                    }
                }
                _ => return Some((i, slot.next.max(now))),
            }
        }
        soonest
    }

    /// Host `i` took an upload at `now`.
    pub fn sent(&mut self, i: usize, now: Instant) {
        if let Some(slot) = self.slots.get_mut(i) {
            slot.next = now + slot.every;
            slot.rests = None;
            self.at = i;
        }
    }

    /// Host `i` refused at `now`: it rests `rest`, and the next host in
    /// order is tried first.
    pub fn refused(&mut self, i: usize, now: Instant, rest: Duration) {
        if let Some(slot) = self.slots.get_mut(i) {
            slot.rests = Some(now + rest);
            slot.next = slot.next.max(now + slot.every);
            self.at = (i + 1) % self.slots.len();
        }
    }

    pub fn host(&self, i: usize) -> Option<Arc<dyn Host>> {
        self.slots.get(i).map(|slot| slot.host.clone())
    }

    /// The host of this name: a note names its host, and the reader fetches
    /// from no other.
    pub fn named(&self, name: &str) -> Option<Arc<dyn Host>> {
        self.slots.iter().find(|slot| slot.host.name() == name).map(|slot| slot.host.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filehost::standin::{Counter, StandInHost};

    #[test]
    fn the_rate_is_under_the_published_one_and_slow_where_none_is_published() {
        // 200 uploads an hour: 160 used, one each 23 s.
        assert_eq!(every(Some(200)), Duration::from_secs(23));
        assert!(every(Some(200)) * 200 > Duration::from_secs(3600), "under the published rate");
        assert_eq!(every(None), UNPUBLISHED_EVERY);
        assert_eq!(every(Some(0)), UNPUBLISHED_EVERY);
        assert_eq!(every(Some(100_000)), LEAST_EVERY, "never closer than the floor");
        assert_eq!(every(Some(1)), Duration::from_secs(3600));
    }

    fn hosts(now: Instant) -> Hosts {
        let counter = Counter::default();
        let a: Arc<dyn Host> = Arc::new(StandInHost::new("a.test", Some(200), counter.clone()));
        let b: Arc<dyn Host> = Arc::new(StandInHost::new("b.test", None, counter).with_most(1024));
        Hosts::new(vec![a, b], now)
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_host_rests_and_the_next_takes_the_piece() {
        let now = Instant::now();
        let mut hosts = hosts(now);
        assert_eq!(hosts.pick(10, now), Some((0, now)));
        hosts.sent(0, now);
        assert_eq!(hosts.pick(10, now), Some((0, now + Duration::from_secs(23))), "the same host, at its pace");
        hosts.refused(0, now, REST);
        assert_eq!(hosts.pick(10, now), Some((1, now)), "the next host while the first rests");
        assert_eq!(hosts.pick(4096, now), Some((0, now + REST)), "a piece that only the first takes waits");
        hosts.refused(1, now, Duration::from_secs(60));
        assert_eq!(hosts.pick(10, now), Some((1, now + Duration::from_secs(60))), "the rest that ends first");
        assert_eq!(hosts.pick(1 << 30, now), None, "no host takes it");
        assert_eq!(hosts.named("b.test").map(|h| h.name().to_string()), Some("b.test".into()));
        assert!(hosts.named("elsewhere.test").is_none());
    }
}
