//! A hook of T-862's measure (`tests/share_lease_measure.rs`): another
//! idle span for the writer lease, and each wait of a held writer. Off, as
//! the product runs, the lease is [`super::share::LEASE_IDLE`] and no wait
//! is kept.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// The idle span in nanoseconds; 0 is the product's constant.
static IDLE_NANOS: AtomicU64 = AtomicU64::new(0);
/// Whether each wait is kept; false keeps nothing, so nothing grows.
static KEEPING: AtomicBool = AtomicBool::new(false);
static WAITS: Mutex<Vec<Duration>> = Mutex::new(Vec::new());

/// The lease's idle span now.
pub(super) fn lease_idle() -> Duration {
    match IDLE_NANOS.load(Ordering::Relaxed) {
        0 => super::share::LEASE_IDLE,
        nanos => Duration::from_nanos(nanos),
    }
}

/// A held write waited `waited` for the lease.
pub(super) fn waited(waited: Duration) {
    if KEEPING.load(Ordering::Relaxed) {
        WAITS.lock().unwrap_or_else(|p| p.into_inner()).push(waited);
    }
}

/// Measure with the idle span `idle` from now on, keeping each wait; None
/// puts back the constant and keeps no more.
#[doc(hidden)]
pub fn measure(idle: Option<Duration>) {
    let nanos = idle.map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1));
    IDLE_NANOS.store(nanos, Ordering::Relaxed);
    KEEPING.store(idle.is_some(), Ordering::Relaxed);
    WAITS.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

/// Each wait kept since [`measure`], and none kept after.
#[doc(hidden)]
pub fn take_waits() -> Vec<Duration> {
    std::mem::take(&mut *WAITS.lock().unwrap_or_else(|p| p.into_inner()))
}
