//! The counts of a shared shell's seats (T-896) apart from SSH:
//! `tests/serve_predict_share.rs` holds the reports through russh.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::predict::report::ECHO_WAIT;

fn offsets(told: &[(u64, Report)]) -> Vec<(u64, u64)> {
    let mut offsets: Vec<_> = told.iter().map(|(seat, report)| (*seat, report.offset)).collect();
    offsets.sort_unstable();
    offsets
}

/// On serve's own tty a byte counts when the discipline reads it, for the
/// seat that wrote it, a read that ends inside a write counting its part;
/// the bytes of a seat that did not ask keep the others' places.
#[tokio::test(start_paused = true)]
async fn on_serve_s_own_tty_each_seat_counts_what_the_discipline_read() {
    let tells = Tells::default();
    tells.source(cooked(), true);
    tells.ask(0);
    tells.ask(1);
    tells.before(0, 3);
    tells.before(2, 2);
    tells.before(1, 4);
    tells.wrote(0, 3);
    tokio::time::advance(ECHO_WAIT).await;
    assert_eq!(offsets(&tells.reports(true).unwrap()), vec![(0, 0), (1, 0)], "written is not read");

    tells.taken(4);
    tokio::time::advance(ECHO_WAIT).await;
    assert_eq!(offsets(&tells.reports(true).unwrap()), vec![(0, 3), (1, 0)], "seat 2's first byte, no ask");
    tells.taken(5);
    tokio::time::advance(ECHO_WAIT).await;
    let told = tells.reports(true).unwrap();
    assert_eq!(offsets(&told), vec![(0, 3), (1, 4)]);
    assert!(told.iter().all(|(_, r)| r.flags == Flags { echo: true, canonical: true }), "the discipline's");
    tells.taken(10);
    assert!(tells.reports(false).is_none(), "a read past each write counts nothing");
}

/// On a kernel pty a byte counts at its write. A report is made again only
/// where it changed, a change of the flags among them; with no seat that
/// asked there is none, and a seat that left has none.
#[tokio::test(start_paused = true)]
async fn on_a_kernel_pty_a_byte_counts_at_its_write_and_a_change_is_told_once() {
    let tells = Tells::default();
    let echo = Arc::new(AtomicBool::new(true));
    let read = echo.clone();
    tells.source(Box::new(move || Flags { echo: read.load(Ordering::SeqCst), canonical: true }), false);
    tells.wrote(5, 2);
    assert!(tells.reports(true).is_none(), "no seat asked");
    tells.ask(5);
    tells.before(5, 9);
    tells.wrote(5, 2);
    tells.taken(9);
    assert_eq!(offsets(&tells.reports(false).unwrap()), vec![(5, 0)], "the first report");
    assert!(tells.reports(false).is_none(), "no change");
    tokio::time::advance(ECHO_WAIT).await;
    assert_eq!(offsets(&tells.reports(false).unwrap()), vec![(5, 2)], "the write alone counts");
    echo.store(false, Ordering::SeqCst);
    assert!(tells.reports(false).unwrap().iter().all(|(_, r)| r.flags.hidden()), "the flags changed");
    assert!(tells.reports(false).is_none());
    tells.leave(5);
    assert!(tells.reports(true).is_none(), "the seat left");
}

/// The wait ends when a write of an asking seat falls due; a write of a
/// seat that did not ask brings none, and with none it never ends.
#[tokio::test(start_paused = true)]
async fn the_wait_ends_when_an_asking_seat_s_write_falls_due() {
    let tells = Arc::new(Tells::default());
    tells.source(cooked(), false);
    tells.ask(1);
    let waiting = tells.clone();
    let wait = tokio::spawn(async move { waiting.fall_due().await });
    tells.wrote(2, 4);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!wait.is_finished(), "no asking seat wrote");
    let start = Instant::now();
    tells.wrote(1, 1);
    wait.await.unwrap();
    assert!(Instant::now() >= start + ECHO_WAIT, "after the echo wait");
    assert_eq!(offsets(&tells.reports(false).unwrap()), vec![(1, 1)]);
}
