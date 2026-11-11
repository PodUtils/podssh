//! The rounds and the verdicts of the burst, against handshakes that a test
//! steers: a limit of N open at once, a failure of each, a silence.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;

/// A handshake that holds 50 ms and fails as `reset` where more than
/// `limit` are open at once.
fn limited(limit: usize) -> impl Fn(Duration) -> std::pin::Pin<Box<dyn Future<Output = Outcome>>> {
    let open = Arc::new(AtomicUsize::new(0));
    move |_bound| {
        let open = open.clone();
        Box::pin(async move {
            let now = open.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
            open.fetch_sub(1, Ordering::SeqCst);
            if now > limit {
                Err("reset")
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_limit_of_three_open_is_a_concurrency_limit_of_three() {
    let rounds = rounds(limited(3)).await;
    assert_eq!((rounds.bursts[0].ok, rounds.bursts[1].ok), (3, 3));
    assert_eq!((rounds.controls[0].ok, rounds.controls[1].ok), (K, K), "the control is clean");
    let Verdict::Failed { detail } = verdict(&rounds) else { panic!("a limit is a failure") };
    assert!(detail.starts_with("concurrency limit: 3/6 handshakes succeed together, 6/6 one at a time"), "{detail}");
    assert!(detail.contains("fails as 6 reset"), "{detail}");
    let numbers = json(&rounds);
    assert_eq!(
        (numbers["k"].as_u64(), numbers["burst_ok"].as_u64(), numbers["control_ok"].as_u64()),
        (Some(6), Some(3), Some(6))
    );
}

#[tokio::test(start_paused = true)]
async fn a_clean_path_shows_no_limit_and_a_failure_of_each_is_not_shown_to_be_one() {
    let clean = rounds(limited(usize::MAX)).await;
    let Verdict::Ok { detail } = verdict(&clean) else { panic!("clean") };
    assert_eq!(detail, "no concurrency limit seen up to 6: 6/6 together twice, 6/6 one at a time twice");
    // Each handshake fails, alone too: no limit is shown, as the burst arm alone would say.
    let each = rounds(|_bound| async { Err::<(), _>("reset") }).await;
    let Verdict::Unknown { why } = verdict(&each) else { panic!("not shown") };
    assert!(why.starts_with("not shown to be a concurrency limit: 6/6 handshakes fail even alone (12 reset)"), "{why}");
}

/// A silent relay: each handshake waits for its bound; the rounds end
/// within the budget, each failure a timeout.
#[tokio::test(start_paused = true)]
async fn a_silent_path_times_out_within_the_budget() {
    let began = Instant::now();
    let silent = |bound: Duration| async move {
        tokio::time::sleep(bound).await;
        Err::<(), _>("timeout")
    };
    let rounds = rounds(silent).await;
    assert!(began.elapsed() <= BUDGET + Duration::from_millis(1), "{:?}", began.elapsed());
    assert!(rounds.bursts.iter().chain(&rounds.controls).any(|r| r.cut), "cut short");
    assert!(rounds.bursts[0].failed.get("timeout") == Some(&K), "{:?}", rounds.bursts[0]);
    let Verdict::Unknown { why } = verdict(&rounds) else { panic!("not shown") };
    assert!(why.contains("timeout") && !why.contains("reset") && why.contains("cut at 10 s"), "{why}");
}

#[test]
fn a_failure_is_classed_by_its_kind() {
    let timeout = ConnectError::Timeout { step: "the TLS handshake", after: Duration::from_secs(8) };
    assert_eq!(class_of(&timeout), "timeout");
    assert_eq!(class_of(&ConnectError::Config("no".into())), "other");
}
