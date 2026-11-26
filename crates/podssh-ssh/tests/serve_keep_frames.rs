//! Frames of a kept shell (T-303 with T-159), with russh's client over pipes
//! in memory and podssh's receiver of the frames: the model of the screen
//! belongs to the shell. A login shell with frames is kept by `~d`'s
//! request; a later login with frames joins it and gets its whole screen
//! first, with what came while no client had it, and no byte; a client of
//! bytes that takes it gets the ring and the output as before; and a shell
//! started with bytes gets a model made from its ring at an attach with
//! frames, whose last frame comes before the status. Each case needs a pty;
//! a host with none says so.

#![cfg(unix)]

mod kept_harness;
mod share_harness;

use std::time::Duration;

use kept_harness::{detach, server, shell_with, states};
use podssh_ssh::frames::receiver::Receiver;
use podssh_ssh::frames::{ACK, ENV};
use share_harness::{have_pty, key, Seat, LIMIT};

/// The ask of frames of version 1, as `podssh ssh --frames` sends it.
const FRAMES: (&str, &str) = (ENV, "v1");

/// What the frames of one channel drew, read as podssh's client reads them,
/// each frame acknowledged.
#[derive(Default)]
struct Framed {
    receiver: Receiver,
    read: usize,
}

impl Framed {
    /// Read the frames of `seat` until the screen that they draw holds
    /// `needle` (or, with "", until the far end's last frame).
    async fn until(&mut self, seat: &Seat, needle: &str) -> String {
        let end = tokio::time::Instant::now() + LIMIT;
        loop {
            let fresh = seat.seen.lock().unwrap().frames[self.read..].to_vec();
            self.read += fresh.len();
            self.receiver.feed(&fresh).expect("frames of this version");
            if let Some(ack) = self.receiver.take_ack() {
                seat.write.set_env(false, ACK, ack.value()).await.unwrap();
            }
            let text = self.receiver.state().map(|state| state.screen.contents()).unwrap_or_default();
            let done = if needle.is_empty() { self.receiver.ended() } else { text.contains(needle) };
            if done {
                return text;
            }
            assert!(tokio::time::Instant::now() < end, "no {needle:?} in the frames in time: {text:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_framed_shell_is_kept_and_an_attach_with_frames_gets_its_whole_screen() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(600), &[&owner]);
    let first = shell_with(&server, &owner, &[FRAMES]).await;
    assert_eq!(first.seen.lock().unwrap().replies, vec![true, true, true], "the pty, the frames, the shell");
    let mut drawn = Framed::default();
    first.send(b"echo FIRST_$((2+3))_END\r").await;
    drawn.until(&first, "FIRST_5_END").await;
    // A line that the shell prints while no client has it.
    first.send(b"(sleep 1; echo LATER_$((6*7))_END) &\r").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(detach(&first, "work").await, "the far end keeps a shell with frames");
    first.until("the channel's close", |seen| seen.closed).await;
    assert!(first.seen.lock().unwrap().out.is_empty(), "a channel with frames gets no byte of the output");
    assert_eq!(states(&server, &owner).await, ["work detached"]);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // An attach with frames: the whole screen first, with what came while
    // no client had the shell; no replay of bytes.
    let second = shell_with(&server, &owner, &[("attach@podssh", "work"), FRAMES]).await;
    assert_eq!(second.seen.lock().unwrap().replies, vec![true, true, true, true]);
    let mut joined = Framed::default();
    let screen = joined.until(&second, "LATER_42_END").await;
    assert!(screen.contains("FIRST_5_END"), "the screen before the detach: {screen:?}");
    second.send(b"echo SECOND_$((4*4))_END\r").await;
    joined.until(&second, "SECOND_16_END").await;
    assert!(second.seen.lock().unwrap().out.is_empty(), "no byte of the ring or of the output");

    // A client of bytes takes it: the ring and the output, as before.
    let third = shell_with(&server, &owner, &[("take@podssh", "yes"), ("attach@podssh", "work")]).await;
    second.until("the taken channel's close", |seen| seen.closed).await;
    third.send(b"echo THIRD_$((3*3))_END\r").await;
    third.reads("THIRD_9_END").await;
    assert!(third.seen.lock().unwrap().frames.is_empty(), "a client of bytes gets no frame");
    third.send(b"exit 0\r").await;
    third.until("the shell's end", |seen| seen.closed).await;
    assert_eq!(third.seen.lock().unwrap().status, Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_of_bytes_gets_a_model_from_its_ring_at_an_attach_with_frames() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(600), &[&owner]);
    let plain = shell_with(&server, &owner, &[]).await;
    plain.send(b"echo PLAIN_$((4+4))_END\r").await;
    plain.reads("PLAIN_8_END").await;
    assert!(detach(&plain, "late").await);
    plain.until("the channel's close", |seen| seen.closed).await;

    let framed = shell_with(&server, &owner, &[("attach@podssh", "late"), FRAMES]).await;
    assert_eq!(framed.seen.lock().unwrap().replies, vec![true, true, true, true]);
    let mut drawn = Framed::default();
    drawn.until(&framed, "PLAIN_8_END").await;
    framed.send(b"echo NOW_$((5+5))_END\r").await;
    drawn.until(&framed, "NOW_10_END").await;
    // The end: the last frame, then the status.
    framed.send(b"exit 3\r").await;
    framed.until("the shell's end", |seen| seen.closed).await;
    drawn.until(&framed, "").await;
    assert_eq!(framed.seen.lock().unwrap().status, Some(3));
    assert!(framed.seen.lock().unwrap().out.is_empty(), "no byte of the ring or of the output");
}
