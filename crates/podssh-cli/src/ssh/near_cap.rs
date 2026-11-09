//! One line on stderr when a relay session of `podssh ssh` has carried the
//! budget of the relay's limits (T-461, GitHub #84): the relay ends the
//! session at its cap, and the output after the cut is lost, so the user
//! hears it first. Not with `-q`, as each line of podssh's at INFO.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::relay_stream::RelayStatus;
use podssh_ssh::Log;

/// How often the count is read: well under the time that a session takes
/// to carry the 4 MiB between the budget and the cap.
const EVERY: Duration = Duration::from_millis(250);

/// The line, for a budget and a cap in bytes.
pub fn line(budget: u64, cap: u64) -> String {
    format!(
        "this relay session has carried {} MiB, and the relay ends it at {} MiB; podssh cp copies more on new sessions",
        budget >> 20,
        cap >> 20
    )
}

/// The budget of this run's relay and its cap: the relay's limits, lowered
/// by `PODSSH_SESSION_BUDGET`, as `podssh cp` reads them (T-137, T-342).
pub fn limits() -> (u64, u64) {
    use podssh_relay::relay;
    let env = std::env::var(relay::SESSION_BUDGET_ENV).ok();
    let budget = relay::byte_budget(env.as_deref());
    let cap = podssh_relay::pool::in_use().max_session_bytes.unwrap_or(relay::session_byte_cap());
    (budget, cap.max(budget))
}

/// Until the payload that `bytes` counts reaches `budget`, then `say` the
/// line once; `bytes` gives `None` once the session ended, which ends this.
pub async fn watch(bytes: impl Fn() -> Option<u64>, budget: u64, cap: u64, say: impl FnOnce(&str)) {
    let mut say = Some(say);
    let lines = vec![(budget, line(budget, cap))];
    watch_lines(bytes, lines, |text| {
        if let Some(say) = say.take() {
            say(text)
        }
    })
    .await;
}

/// The lines of `podssh sftp` (T-700): at 80 % and at 95 % of the budget,
/// as `(bytes, line)` in the order they come. Its meter stops a transfer
/// at the budget, so the user hears the nearing, not the cap.
pub fn sftp_marks(budget: u64, cap: u64) -> Vec<(u64, String)> {
    [80u64, 95]
        .into_iter()
        .map(|pct| {
            let line = format!(
                "this relay session has carried {pct} % of the {} MiB that podssh sftp sends on one, and the relay ends it at {} MiB; a transfer that needs more stops, and podssh cp copies more on new sessions",
                budget >> 20,
                cap >> 20
            );
            (budget / 100 * pct + budget % 100 * pct / 100, line)
        })
        .collect()
}

/// Each of `lines` (bytes, text) once, in order, when the payload that
/// `bytes` counts reaches its bytes; two passed in one look come both. Ends
/// after the last line, or when `bytes` gives `None`.
pub async fn watch_lines(bytes: impl Fn() -> Option<u64>, lines: Vec<(u64, String)>, mut say: impl FnMut(&str)) {
    let mut lines = std::collections::VecDeque::from(lines);
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !lines.is_empty() {
        tick.tick().await;
        let Some(carried) = bytes() else { return };
        while lines.front().is_some_and(|(at, _)| carried >= *at) {
            let (_, text) = lines.pop_front().expect("a line");
            say(&text);
        }
    }
}

/// [`watch`] of a relay session, on a task of its own; the caller aborts it
/// when the run ends.
pub fn spawn(status: RelayStatus, log: Arc<Log>) -> tokio::task::JoinHandle<()> {
    let (budget, cap) = limits();
    tokio::spawn(async move {
        let counted = status.clone();
        let bytes = move || counted.get().is_none().then(|| counted.bytes());
        watch(bytes, budget, cap, |line| log.info(line)).await;
    })
}

/// [`watch_lines`] of an SFTP session's meter, at 80 % and 95 % of its
/// budget, on a task of its own; `None` where no relay carries the session
/// or `-q` hides the lines. The caller aborts it when the session closes.
pub fn spawn_sftp(meter: crate::cp::link::Meter, log: Arc<Log>) -> Option<tokio::task::JoinHandle<()>> {
    if !meter.through_relay() || log.level() < podssh_ssh::LogLevel::Info {
        return None;
    }
    let marks = sftp_marks(meter.budget(), limits().1);
    Some(tokio::spawn(async move {
        watch_lines(|| meter.carried(), marks, |line| log.info(line)).await;
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn the_line_names_the_budget_and_the_cap() {
        assert_eq!(
            line(60 * MIB, 64 * MIB),
            "this relay session has carried 60 MiB, and the relay ends it at 64 MiB; podssh cp copies more on new sessions"
        );
    }

    /// Under the budget nothing is said; past it, the line once, and the
    /// watch ends.
    #[tokio::test(start_paused = true)]
    async fn the_line_comes_once_past_the_budget() {
        let carried = Arc::new(AtomicU64::new(0));
        let said = Arc::new(Mutex::new(Vec::new()));
        let (count, into) = (carried.clone(), said.clone());
        let watching = tokio::spawn(async move {
            let bytes = move || Some(count.load(Ordering::SeqCst));
            watch(bytes, 60 * MIB, 64 * MIB, |line| into.lock().unwrap().push(line.to_string())).await;
        });
        carried.store(59 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(said.lock().unwrap().is_empty(), "nothing under the budget");
        carried.store(60 * MIB + 1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(watching.is_finished(), "the watch ends after its line");
        assert_eq!(said.lock().unwrap().as_slice(), [line(60 * MIB, 64 * MIB)]);
    }

    /// A session that ended under the budget ends the watch with no line.
    #[tokio::test(start_paused = true)]
    async fn an_ended_session_says_nothing() {
        let ended = Arc::new(AtomicU64::new(0));
        let said = Arc::new(Mutex::new(Vec::new()));
        let (flag, into) = (ended.clone(), said.clone());
        let watching = tokio::spawn(async move {
            let bytes = move || (flag.load(Ordering::SeqCst) == 0).then_some(MIB);
            watch(bytes, 60 * MIB, 64 * MIB, |line| into.lock().unwrap().push(line.to_string())).await;
        });
        ended.store(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(watching.is_finished());
        assert!(said.lock().unwrap().is_empty());
    }

    /// The lines of sftp: 80 % then 95 %, each once and in order, whatever
    /// the steps of the count; the watch ends after the second.
    #[tokio::test(start_paused = true)]
    async fn sftp_says_80_then_95_once_each() {
        let carried = Arc::new(AtomicU64::new(0));
        let said = Arc::new(Mutex::new(Vec::new()));
        let (count, into) = (carried.clone(), said.clone());
        let watching = tokio::spawn(async move {
            let bytes = move || Some(count.load(Ordering::SeqCst));
            watch_lines(bytes, sftp_marks(100 * MIB, 128 * MIB), |l| into.lock().unwrap().push(l.to_string())).await;
        });
        let seen = || said.lock().unwrap().len();
        carried.store(79 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(seen(), 0);
        carried.store(80 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(seen(), 1, "80 % once, however long the count stays");
        carried.store(94 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(seen(), 1);
        carried.store(95 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(watching.is_finished());
        let said = said.lock().unwrap();
        assert!(said[0].contains("80 %") && said[1].contains("95 %"), "{said:?}");
    }

    /// A jump past both marks in one look says both, in order.
    #[tokio::test(start_paused = true)]
    async fn sftp_says_both_when_the_count_jumps() {
        let said = Arc::new(Mutex::new(Vec::new()));
        let into = said.clone();
        watch_lines(|| Some(100 * MIB), sftp_marks(100 * MIB, 128 * MIB), |l| into.lock().unwrap().push(l.to_string()))
            .await;
        let said = said.lock().unwrap();
        assert_eq!(said.len(), 2);
        assert!(said[0].contains("80 %") && said[1].contains("95 %"));
    }

    /// An ended session says nothing more, and the marks are of the budget.
    #[tokio::test(start_paused = true)]
    async fn sftp_says_nothing_after_the_end() {
        let said = Arc::new(Mutex::new(Vec::new()));
        let into = said.clone();
        watch_lines(|| None, sftp_marks(MIB, 64 * MIB), |l| into.lock().unwrap().push(l.to_string())).await;
        assert!(said.lock().unwrap().is_empty());
        let at: Vec<u64> = sftp_marks(1 << 20, 64 << 20).iter().map(|m| m.0).collect();
        assert_eq!(at, [838_860, 996_147]);
    }

    /// With no relay there is no watch.
    #[tokio::test]
    async fn sftp_spawns_no_watch_without_a_relay() {
        let log = Arc::new(Log::new(podssh_ssh::LogLevel::Info));
        assert!(spawn_sftp(crate::cp::link::Meter::new(None), log).is_none());
    }
}
