//! The open connections of the relay role's listener, bounded (T-748): a
//! slot for each accepted TCP connection, held for its life and counted by
//! the address that it came from (`Who`: an IPv4 address, or the /64 of an
//! IPv6 one) and in all. A connection over either cap is closed at once,
//! before TLS, so that it costs the role nothing, and said once a minute for
//! its address. A failed `accept` (most often the descriptors spent) pauses
//! the loop, which else retries at once and takes a whole core while each
//! client is refused. A peer on the loopback is a proxy or the edge in front
//! of the role, whose visitors would else share one count: it counts in all
//! alone.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::brake::Who;

/// The default cap of each address: one client session holds one
/// connection, so this leaves room for an office behind one address.
pub const PER_ADDRESS: usize = 256;
/// The pause after a failed `accept`.
pub const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// One line for each address that the caps refuse, at most this often.
const SAID_EVERY: Duration = Duration::from_secs(60);

/// The caps: 0 is no cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps {
    pub per_address: usize,
    pub total: usize,
}

#[derive(Default)]
struct Held {
    by: HashMap<Who, usize>,
    total: usize,
    said: HashMap<Who, Instant>,
    failed_said: Option<Instant>,
}

/// The listener's count of open connections.
#[derive(Clone, Default)]
pub struct Slots {
    caps: Caps,
    held: Arc<Mutex<Held>>,
}

/// One connection's place, given back when it drops.
pub struct Slot {
    held: Arc<Mutex<Held>>,
    who: Option<Who>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.total = held.total.saturating_sub(1);
        if let Some(who) = self.who {
            if let Some(n) = held.by.get_mut(&who) {
                *n -= 1;
                if *n == 0 {
                    held.by.remove(&who);
                }
            }
        }
    }
}

impl Slot {
    /// `connection`, with this slot held until it ends.
    pub async fn holding<F: Future>(self, connection: F) -> F::Output {
        let _slot = self;
        connection.await
    }
}

impl Slots {
    pub fn new(caps: Caps) -> Slots {
        Slots { caps, held: Arc::default() }
    }

    /// A slot for a connection from `peer`, or why not: a line to say, at
    /// most once a minute for each address, else `Err(None)`.
    pub fn admit(&self, peer: IpAddr) -> Result<Slot, Option<String>> {
        let who = (!peer.is_loopback()).then(|| Who::of(Some(peer)));
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let over_total = self.caps.total > 0 && held.total >= self.caps.total;
        let mine = who.map(|who| held.by.get(&who).copied().unwrap_or(0)).unwrap_or(0);
        let over_address = who.is_some() && self.caps.per_address > 0 && mine >= self.caps.per_address;
        if over_total || over_address {
            let key = who.unwrap_or(Who::Unknown);
            let now = Instant::now();
            let say = held.said.get(&key).is_none_or(|last| now.duration_since(*last) >= SAID_EVERY);
            if !say {
                return Err(None);
            }
            held.said.insert(key, now);
            let why = match over_total {
                true => format!("refused a connection from {peer}: {} connections are open, the cap", held.total),
                false => format!("refused a connection from {peer}: its address holds {mine}, the cap of each address"),
            };
            return Err(Some(why));
        }
        held.total += 1;
        if let Some(who) = who {
            *held.by.entry(who).or_insert(0) += 1;
        }
        Ok(Slot { held: self.held.clone(), who })
    }

    /// The line to say for a failed `accept`, at most once a minute; the
    /// caller pauses [`ACCEPT_PAUSE`] either way.
    pub fn accept_failed(&self, why: &std::io::Error) -> Option<String> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if held.failed_said.is_some_and(|last| now.duration_since(last) < SAID_EVERY) {
            return None;
        }
        held.failed_said = Some(now);
        Some(format!(
            "the listener could not accept ({why}); it pauses {} ms after each failure",
            ACCEPT_PAUSE.as_millis()
        ))
    }

    /// The connections open now: in all, and from `peer`'s address.
    pub fn open(&self, peer: IpAddr) -> (usize, usize) {
        let held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        (held.total, held.by.get(&Who::of(Some(peer))).copied().unwrap_or(0))
    }

    pub fn caps(&self) -> Caps {
        self.caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_address_over_its_cap_is_refused_until_one_of_its_connections_ends() {
        let slots = Slots::new(Caps { per_address: 2, total: 0 });
        let (a, b) = (slots.admit(ip("192.0.2.1")).ok().unwrap(), slots.admit(ip("192.0.2.1")).ok().unwrap());
        let refused = slots.admit(ip("192.0.2.1")).err().unwrap();
        assert!(refused.unwrap().contains("the cap of each address"));
        assert!(matches!(slots.admit(ip("192.0.2.1")), Err(None)), "said once a minute");
        assert!(slots.admit(ip("192.0.2.2")).is_ok(), "another address has its own count");
        drop(a);
        assert!(slots.admit(ip("192.0.2.1")).is_ok(), "a place freed is taken again");
        drop(b);
    }

    #[test]
    fn two_addresses_of_one_slash_64_share_a_count_and_the_loopback_counts_in_all_alone() {
        let slots = Slots::new(Caps { per_address: 1, total: 3 });
        let _one = slots.admit(ip("2001:db8:1:2::10")).ok().unwrap();
        assert!(slots.admit(ip("2001:db8:1:2::20")).is_err(), "the /64 holds one");
        let _proxy = (slots.admit(ip("127.0.0.1")).ok().unwrap(), slots.admit(ip("::1")).ok().unwrap());
        assert_eq!(slots.open(ip("2001:db8:1:2::99")), (3, 1));
        let refused = slots.admit(ip("198.51.100.7")).err().unwrap().unwrap();
        assert!(refused.contains("3 connections are open, the cap"), "{refused}");
    }

    #[test]
    fn no_cap_is_no_count_that_refuses_and_a_failed_accept_is_said_once_a_minute() {
        let slots = Slots::new(Caps::default());
        let held: Vec<Slot> = (0..1000).map(|_| slots.admit(ip("192.0.2.1")).ok().unwrap()).collect();
        assert_eq!(slots.open(ip("192.0.2.1")), (1000, 1000));
        drop(held);
        assert_eq!(slots.open(ip("192.0.2.1")), (0, 0), "each slot given back");
        let why = std::io::Error::from_raw_os_error(24);
        assert!(slots.accept_failed(&why).is_some_and(|line| line.contains("pauses 100 ms")));
        assert!(slots.accept_failed(&why).is_none());
    }
}
