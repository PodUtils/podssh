//! The trace of a member (`PODSSH_ZT_TRACE=1`), for a run that is slow or
//! fails: each 2 s, to stderr, the datagrams of the wire by address, each
//! way, and the frames of the network each way, since the member started.
//! Off, each call is one load of a flag.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The variable that turns the trace on.
pub const ENV: &str = "PODSSH_ZT_TRACE";

/// A member's counts.
#[derive(Default)]
pub struct Trace {
    on: AtomicBool,
    by_address: Mutex<BTreeMap<SocketAddr, (u64, u64)>>,
    frames_in: AtomicU64,
    frames_out: AtomicU64,
}

impl Trace {
    /// A trace, on when [`ENV`] is `1`.
    pub fn from_env() -> Arc<Trace> {
        let trace = Trace::default();
        trace.on.store(std::env::var(ENV).is_ok_and(|v| v == "1"), Ordering::Relaxed);
        Arc::new(trace)
    }

    fn count(&self, at: SocketAddr, out: bool) {
        if self.on.load(Ordering::Relaxed) {
            let mut by = self.by_address.lock().unwrap_or_else(|e| e.into_inner());
            let entry = by.entry(at).or_default();
            if out {
                entry.0 += 1
            } else {
                entry.1 += 1
            }
        }
    }

    /// A datagram sent to `to`.
    pub fn sent(&self, to: SocketAddr) {
        self.count(to, true);
    }

    /// A datagram that came from `from`.
    pub fn came(&self, from: SocketAddr) {
        self.count(from, false);
    }

    /// A frame of the network that came to this member.
    pub fn frame_in(&self) {
        self.frames_in.fetch_add(1, Ordering::Relaxed);
    }

    /// A frame that this member sent.
    pub fn frame_out(&self) {
        self.frames_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Start the lines of the member `address`, while the trace lives.
    pub fn start(self: &Arc<Self>, address: u64) {
        if !self.on.load(Ordering::Relaxed) {
            return;
        }
        let (trace, began) = (Arc::downgrade(self), Instant::now());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let Some(trace) = trace.upgrade() else { return };
                let line = format!("zt {address:010x} {:>5.1}s {}\n", began.elapsed().as_secs_f64(), trace.line());
                // A trace that cannot be written is not worth a panic.
                let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
            }
        });
    }

    /// The counts as one line: frames out/in, then each address out/in.
    fn line(&self) -> String {
        let by = self.by_address.lock().unwrap_or_else(|e| e.into_inner());
        let wire: Vec<String> = by.iter().map(|(at, (out, came))| format!("{at} {out}/{came}")).collect();
        let (out, came) = (self.frames_out.load(Ordering::Relaxed), self.frames_in.load(Ordering::Relaxed));
        format!("frames {out}/{came}; wire {}", wire.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_counts_each_way_by_address() {
        let trace = Trace::default();
        trace.on.store(true, Ordering::Relaxed);
        let root: SocketAddr = "198.51.100.1:9993".parse().unwrap();
        trace.sent(root);
        trace.sent(root);
        trace.came(root);
        trace.frame_out();
        assert_eq!(trace.line(), "frames 1/0; wire 198.51.100.1:9993 2/1");
        // Off, nothing is kept.
        let off = Trace::default();
        off.sent(root);
        assert_eq!(off.line(), "frames 0/0; wire ");
    }
}
