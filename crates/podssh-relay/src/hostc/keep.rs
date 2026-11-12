//! The node's tunnel, kept: one socket at a time, opened again after a drop
//! with a wait that doubles from 1 s to 30 s. A tunnel keeps its name for 10
//! minutes after a drop, so the node asks for a new one only when the
//! server says that the tunnel is gone (`401`, `404`) or that time passed;
//! each new tunnel waits [`CREATE_GAP`] after the last, so the node never
//! asks for more than the server's 20 a minute. A `426` ends the road: the
//! server speaks another version, which only a newer podssh speaks.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::api::{self, Dial, Failed, Tunnel};
use super::link::{self, Beat, Ended};
use super::{Service, CREATE_LIMIT, RECONNECT_GRACE};
use crate::pinggy::far::Visitor;
use crate::pinggy::Say;

/// The shortest time between two tunnels asked: the server's limit for one
/// address, a minute over [`CREATE_LIMIT`].
pub const CREATE_GAP: Duration = Duration::from_millis(60_000 / CREATE_LIMIT as u64);
/// The longest wait between two tries.
pub const MOST_WAIT: Duration = Duration::from_secs(30);

/// What the node keeps its tunnel with.
#[derive(Clone)]
pub struct Keep {
    pub service: Service,
    pub dial: Dial,
    pub say: Say,
    pub beat: Beat,
}

/// The wait before try `attempt` (0 first): 1 s, doubled, at most [`MOST_WAIT`].
pub fn wait_of(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(5)).min(MOST_WAIT)
}

/// The first tunnel, asked.
pub async fn first(keep: &Keep) -> Result<Tunnel, Failed> {
    api::create(&keep.service, &keep.dial).await
}

/// Keep `tunnel` until a stop: each socket's streams go to `visitors`;
/// `made` hears of each new tunnel. `Err` ends the road, with why.
pub async fn run(
    keep: Keep,
    mut tunnel: Tunnel,
    visitors: mpsc::Sender<Visitor>,
    made: impl Fn(&Tunnel),
    stopped: watch::Receiver<bool>,
) -> Result<(), String> {
    let (service, say) = (&keep.service, &keep.say);
    let mut attempt = 0u32;
    // Since when the tunnel has no socket, and when a tunnel was last asked.
    let mut dropped: Option<Instant> = None;
    let mut asked = Instant::now();
    let is_stopped = |stopped: &watch::Receiver<bool>| *stopped.borrow();
    loop {
        if is_stopped(&stopped) {
            return Ok(());
        }
        let gone = match api::connect(service, &tunnel, &keep.dial).await {
            Ok((io, pending)) => {
                // The socket's own end sets `dropped` again below.
                attempt = 0;
                let name = tunnel.host.clone();
                match link::serve(io, pending, name, visitors.clone(), keep.beat, stopped.clone()).await {
                    Ended::Stopped => return Ok(()),
                    Ended::Dropped(why) | Ended::Protocol(why) => {
                        say(format!("the tunnel's socket at {service} ended: {why}; the node opens another"));
                        dropped = Some(Instant::now());
                        false
                    }
                }
            }
            Err(Failed::Version(why)) => return Err(why),
            Err(Failed::Gone(why)) => {
                say(format!("the tunnel {} is gone ({why}); the node asks for a new one", tunnel.host));
                true
            }
            Err(Failed::Refused(why) | Failed::ForNow(why)) => {
                let since = *dropped.get_or_insert_with(Instant::now);
                say(format!("no socket of the tunnel at {service}: {why}; again in a while"));
                since.elapsed() >= RECONNECT_GRACE
            }
        };
        if gone {
            // Within the server's limit of tunnels a minute.
            let gap = CREATE_GAP.saturating_sub(asked.elapsed());
            if !sleep_or_stop(gap, stopped.clone()).await {
                return Ok(());
            }
            asked = Instant::now();
            match api::create(service, &keep.dial).await {
                Ok(new) => {
                    tunnel = new;
                    dropped = None;
                    made(&tunnel);
                    continue;
                }
                Err(Failed::Version(why)) => return Err(why),
                Err(why) => say(format!("no new tunnel at {service}: {why}; again in a while")),
            }
        }
        let wait = wait_of(attempt);
        attempt = attempt.saturating_add(1);
        if !sleep_or_stop(wait, stopped.clone()).await {
            return Ok(());
        }
    }
}

/// Wait `wait`; false when the node stopped first.
async fn sleep_or_stop(wait: Duration, mut stopped: watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(wait) => true,
        () = link::stop_of(&mut stopped) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_waits_double_to_their_bound_and_tunnels_stay_within_the_server_s_limit() {
        let waits: Vec<u64> = (0..8).map(|n| wait_of(n).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(CREATE_GAP, Duration::from_secs(3));
        assert!(60_000 / CREATE_GAP.as_millis() <= u128::from(CREATE_LIMIT));
    }
}
