//! The target of a channel's window (T-661), a pure function of what the
//! connection measured, whether a key was typed lately, and the road's cap;
//! and the room left under which russh tops a window up to it (T-670).

use std::time::Duration;

/// The least window while a key waits: a few packets, so that a bulk
/// channel never stops, and its adjusts are no burden.
pub const FLOOR: u32 = 16 * 1024;

/// The window before anything was measured, as podssh gave each channel
/// before T-661: russh advertises it when a channel opens.
pub const START: u32 = crate::run::WINDOW;

/// While a key was typed lately: what a key may wait behind, beyond the
/// path's own round trip, or one message at the path's rate when that is
/// longer, so that a slow path never runs dry between messages. 40 ms held
/// a queue of 40 to 73 ms in front of each key on osewa's cellular link,
/// where osewa holds about 11 ms (T-681).
pub const TYPING_MARGIN: Duration = Duration::from_millis(10);

/// With a rate and no round trip timed yet, the most of the rate that a
/// window holds: on a slow path, [`START`] is seconds of queue, and a window
/// that never gates a byte never times a round trip (T-681); one this big
/// gates, so the next adjusts time it.
pub const UNTIMED: Duration = Duration::from_millis(500);

/// Idle: room for the rate to vary, and the wait of the first key after a
/// pause.
pub const IDLE_MARGIN: Duration = Duration::from_millis(200);

/// Measured, russh tops a window up to its target once a quarter of it is
/// used ([`low`]), so three quarters of a target are in flight at least: the
/// target is that much larger than the path's bytes of its round trip and
/// margin, which then always fill the path, and a window that limits the
/// rate lets three quarters of itself through each round trip, so the rate
/// that it measures gives a larger target, by the margin.
const SAWTOOTH: f64 = 4.0 / 3.0;

/// What a channel's target is made of.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Inputs {
    /// A key was typed in the last 2 s.
    pub typing: bool,
    /// The windows drain, so that the least round trip is timed afresh.
    pub draining: bool,
    /// The channel carries a `-J` hop's next connection.
    pub carrier: bool,
    /// The path's rate, bytes a second, when measured lately.
    pub rate: Option<u64>,
    /// The path's least round trip, when measured.
    pub rtt: Option<Duration>,
    /// The channels that share the rate now: 1 at least.
    pub sharing: u32,
    /// The most that the road takes for one channel.
    pub cap: u32,
}

/// The target of a channel's window.
///
/// - A carrier gets the cap: the connection inside it bounds its own
///   channels, and a smaller window would only queue at the hop.
/// - While the windows drain, [`FLOOR`].
/// - Unmeasured, [`START`] idle, [`FLOOR`] while a key waits; with a rate
///   and no round trip yet, idle, [`UNTIMED`] of the rate, at most [`START`].
/// - Else the path's rate times its least round trip plus the margin, and a
///   third more, its share of it, at least [`FLOOR`] and at most its share
///   of the cap (T-662), which is never under [`START`]: channels that carry
///   bulk together share what the road holds, and none gets less than
///   before.
pub fn of(i: &Inputs) -> u32 {
    let cap = i.cap.max(FLOOR);
    if i.carrier {
        return cap;
    }
    if i.draining {
        return FLOOR;
    }
    let start = START.min(cap);
    let Some(rate) = i.rate else {
        return if i.typing { FLOOR } else { start };
    };
    let Some(rtt) = i.rtt else {
        return if i.typing { FLOOR } else { clamp(rate as f64 * UNTIMED.as_secs_f64(), start) };
    };
    let margin = if i.typing {
        let message = Duration::try_from_secs_f64(f64::from(super::PACKET) / rate.max(1) as f64);
        TYPING_MARGIN.max(message.unwrap_or(IDLE_MARGIN).min(IDLE_MARGIN))
    } else {
        IDLE_MARGIN
    };
    let sharing = i.sharing.max(1);
    let held = rate as f64 * (rtt + margin).as_secs_f64() * SAWTOOTH;
    let share = (cap / sharing).max(START.min(cap));
    clamp(held / f64::from(sharing), share)
}

/// The room left in a window under which russh tops it up to `target`.
///
/// Measured, once a quarter of the target is used. russh's own rule, half,
/// waits for half a window to come before the next adjust, so a window that
/// limits the rate lets about half of itself through each round trip: the
/// rate that it measures then gives back the same window, and it never
/// grows (T-670). Unmeasured, russh's half, as with the window of before.
pub fn low(target: u32, measured: bool) -> u32 {
    if measured {
        target - target / 4
    } else {
        target / 2
    }
}

/// `bytes`, within [`FLOOR`] and `cap`.
fn clamp(bytes: f64, cap: u32) -> u32 {
    if bytes.is_nan() || bytes <= f64::from(FLOOR) {
        FLOOR
    } else if bytes >= f64::from(cap) {
        cap
    } else {
        bytes as u32
    }
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
