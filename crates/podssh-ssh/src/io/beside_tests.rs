//! The cycle of T-780 in small, with no russh: a loop that puts messages
//! into a channel's queue of 2, inline, and takes the pump's writes from a
//! full queue of its own only after them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use super::model::Model;
use super::*;

/// Longer than any step of the model takes; the clock is paused, so a wait
/// that never ends runs out at once.
const LIMIT: Duration = Duration::from_secs(60);

/// russh's loop, in small (`model`), with `count` messages of 100 bytes.
fn model(count: u8) -> Model<Vec<u8>> {
    super::model::model((0..count).map(|i| vec![i; 100]).collect())
}

/// The write awaited alone waits for ever on the loop, which waits on the
/// pump (the control); beside the channel it goes, and each message is
/// handed on after, in order, then the channel's end.
#[tokio::test(start_paused = true)]
async fn a_write_beside_the_channel_breaks_the_cycle() {
    let (chan, cmd, looping) = model(8);
    let alone = tokio::time::timeout(LIMIT, cmd.send("eof")).await;
    assert!(alone.is_err(), "the control: a write that drains nothing waits for ever");
    looping.abort();
    drop(chan);

    let (mut chan, cmd, looping) = model(8);
    let mut backlog = Backlog::default();
    let polls = AtomicUsize::new(0);
    let polled = || {
        polls.fetch_add(1, Ordering::Relaxed);
    };
    let sent = tokio::time::timeout(LIMIT, beside(cmd.send("eof"), &mut chan, &mut backlog, &polled)).await;
    assert!(matches!(sent, Ok(Ok(()))), "the write went beside the channel");
    assert!(polls.load(Ordering::Relaxed) > 0, "each poll of the channel's wait is told");
    assert_eq!(looping.await.expect("the loop ends"), ["data", "eof"]);
    for i in 0..8 {
        assert_eq!(next(&mut chan, &mut backlog).await, Some(vec![i; 100]), "message {i}, in order");
    }
    assert_eq!(next(&mut chan, &mut backlog).await, None, "then the channel's end");
}

/// A backlog at its bound drains no more: the write then waits on the loop,
/// as it did before, and no more is kept.
#[tokio::test(start_paused = true)]
async fn a_full_backlog_drains_no_more() {
    let (mut chan, cmd, looping) = model(8);
    let mut backlog = Backlog::with_most(250);
    let sent = tokio::time::timeout(LIMIT, beside(cmd.send("eof"), &mut chan, &mut backlog, &|| {})).await;
    assert!(sent.is_err(), "past the bound the write waits");
    assert_eq!(backlog.len(), 3, "100 bytes each, until 250 are passed");
    looping.abort();
}

/// A channel that ends during the wait is kept as its end: the messages
/// before it are handed on, then `None`, with no read of the channel.
#[tokio::test(start_paused = true)]
async fn the_end_of_the_channel_is_kept_behind_its_messages() {
    let (chan_tx, mut chan) = mpsc::channel(4);
    for i in 0..2u8 {
        chan_tx.try_send(vec![i; 10]).expect("room");
    }
    drop(chan_tx);
    let (done_tx, done) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = done_tx.send(());
    });
    let mut backlog = Backlog::default();
    let finished = tokio::time::timeout(LIMIT, beside(done, &mut chan, &mut backlog, &|| {})).await;
    assert!(matches!(finished, Ok(Ok(()))), "the wait ends on its own");
    assert_eq!(backlog.len(), 2);
    assert_eq!(next(&mut chan, &mut backlog).await, Some(vec![0; 10]));
    assert_eq!(next(&mut chan, &mut backlog).await, Some(vec![1; 10]));
    assert_eq!(next(&mut chan, &mut backlog).await, None);
}

/// The lines of the body of the item that starts with `start`: up to the
/// line that closes it, at the indent of the line where it starts.
fn body<'a>(file: &str, text: &'a str, start: &str) -> impl Iterator<Item = &'a str> {
    let at = text.find(start).unwrap_or_else(|| panic!("{file}: no {start}"));
    let line = text[..at].rfind('\n').map_or(0, |n| n + 1);
    let indent: String = text[line..].chars().take_while(|c| *c == ' ').collect();
    let close = format!("{indent}}}");
    text[at..].lines().take_while(move |line| *line != close)
}

/// The session's writer and handle, by the names that most pumps give them.
const SESSION: &[&str] = &["writer", "handle"];

/// A pump: its file, its text, the start of its body, the names of the
/// session's writes there, and the calls that drain the channel themselves.
type Pump = (&'static str, &'static str, &'static str, &'static [&'static str], &'static [&'static str]);

/// Beside the pumps of the session (T-780) and the send that waits for the
/// window (T-859): `exec`'s upload and its end of input, the two sides of
/// serve's gateway, and `podssh ping`'s measures (T-923). `load.rs` names
/// no handle: its waits on the handle open channels while cat's channel
/// holds nothing unread; `keys::typed` reads cat's channel beside each key.
#[rustfmt::skip]
const PUMPS: &[Pump] = &[
    ("io.rs", include_str!("../io.rs"), "pub async fn pump(", SESSION, &["send(&writer"]),
    ("mux/msession.rs", include_str!("../mux/msession.rs"), "async fn pump(", SESSION, &["send(&writer"]),
    ("io/send.rs", include_str!("send.rs"), "pub(super) async fn send(", SESSION, &["send(&writer"]),
    ("exec.rs", include_str!("../exec.rs"), "pub async fn receive(", &["writer"], &["end_input(&writer"]),
    ("exec.rs", include_str!("../exec.rs"), "pub async fn send(", &["writer"], &["write(writer", "end_input(&writer"]),
    ("exec.rs", include_str!("../exec.rs"), "async fn end_input(", &["writer"], &["write(writer"]),
    ("server/gateway/pump.rs", include_str!("../server/gateway/pump.rs"), "async fn from_client(", &["up"], &[]),
    ("server/gateway/pump.rs", include_str!("../server/gateway/pump.rs"), "async fn from_upstream(", &["down", "handle"], &[]),
    ("ping/far.rs", include_str!("../../../podssh-cli/src/ping/far.rs"), "pub async fn echo(", &["writer"], &[]),
    ("ping/far.rs", include_str!("../../../podssh-cli/src/ping/far.rs"), "pub async fn up(", &["writer"], &[]),
    ("ping/load.rs", include_str!("../../../podssh-cli/src/ping/load.rs"), "pub async fn measure(", &["writer", "load_writer"], &["keys::typed(&writer"]),
];

/// Each wait of a pump on the session goes beside its channel: in the body
/// of each pump of [`PUMPS`], a line that awaits and names one of its
/// session's writes is a call of `beside`, or of a call that drains the
/// channel itself. A wait that drains nothing is the cycle above.
#[test]
fn each_wait_of_a_pump_on_the_session_goes_beside_the_channel() {
    for (file, text, start, names, drains) in PUMPS {
        let mut waits = 0;
        for line in body(file, text, start).filter(|line| line.contains(".await")) {
            let mut words = line.split(|c: char| !(c.is_alphanumeric() || c == '_'));
            if !words.any(|word| names.contains(&word)) {
                continue;
            }
            waits += 1;
            assert!(
                line.contains("beside(") || drains.iter().any(|call| line.contains(call)),
                "{file}, {start}: a wait on the session that drains nothing: {}",
                line.trim()
            );
        }
        assert!(waits > 0, "{file}, {start}: the pump's waits were found");
    }
    // The wait of an elevated command, which the pump runs in its select
    // and not beside the channel, writes nothing: the pump sends its answer
    // beside the channel (T-923).
    for line in body("elevate.rs", include_str!("../elevate.rs"), "pub async fn next(") {
        assert!(!line.contains("writer"), "elevate.rs: a write in the wait of its question: {}", line.trim());
    }
}
