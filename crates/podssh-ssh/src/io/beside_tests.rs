//! The cycle of T-780 in small, with no russh: a loop that puts messages
//! into a channel's queue of 2, inline, and takes the pump's writes from a
//! full queue of its own only after them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::*;

/// Longer than any step of the model takes; the clock is paused, so a wait
/// that never ends runs out at once.
const LIMIT: Duration = Duration::from_secs(60);

impl Source for mpsc::Receiver<Vec<u8>> {
    type Msg = Vec<u8>;

    fn wait(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send + '_ {
        self.recv()
    }

    fn size(msg: &Vec<u8>) -> usize {
        msg.len()
    }
}

/// The channel's queue, the loop's queue of writes, and the loop.
type Model = (mpsc::Receiver<Vec<u8>>, mpsc::Sender<&'static str>, JoinHandle<Vec<&'static str>>);

/// russh's loop, in small: it puts `count` messages of 100 bytes into the
/// channel's queue of 2, each awaited inline, and only then takes the
/// pump's writes, from a queue of 1 that one write fills already. It gives
/// the writes that it took, up to the EOF.
fn model(count: u8) -> Model {
    let (chan_tx, chan_rx) = mpsc::channel(2);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
    cmd_tx.try_send("data").expect("an empty queue of 1");
    let looping = tokio::spawn(async move {
        for i in 0..count {
            if chan_tx.send(vec![i; 100]).await.is_err() {
                break;
            }
        }
        let mut took = Vec::new();
        while let Some(cmd) = cmd_rx.recv().await {
            took.push(cmd);
            if cmd == "eof" {
                break;
            }
        }
        took
    });
    (chan_rx, cmd_tx, looping)
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

/// Each wait of a pump on the session goes beside its channel: in the body
/// of each pump, a line that awaits and names the writer or the handle is a
/// call of `beside`, or of `send`, which drains the channel itself. A wait
/// that drains nothing is the cycle above.
#[test]
fn each_wait_of_a_pump_on_the_session_goes_beside_the_channel() {
    let pumps = [
        ("io.rs", include_str!("../io.rs"), "pub async fn pump("),
        ("mux/msession.rs", include_str!("../mux/msession.rs"), "async fn pump("),
    ];
    for (file, text, start) in pumps {
        let at = text.find(start).unwrap_or_else(|| panic!("{file}: no {start}"));
        // The body ends at the first line that closes an item.
        let body = text[at..].lines().take_while(|line| *line != "}");
        let mut waits = 0;
        for line in body.filter(|line| line.contains(".await")) {
            let mut words = line.split(|c: char| !(c.is_alphanumeric() || c == '_'));
            if !words.any(|word| word == "writer" || word == "handle") {
                continue;
            }
            waits += 1;
            assert!(
                line.contains("beside(") || line.contains("send(&writer"),
                "{file}: a wait on the session that drains nothing: {}",
                line.trim()
            );
        }
        assert!(waits > 0, "{file}: the pump's waits were found");
    }
}
