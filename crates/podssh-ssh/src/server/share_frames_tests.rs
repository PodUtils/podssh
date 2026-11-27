//! A shared shell's model of its screen (T-303 with T-837) apart from SSH:
//! one model for the shell, the owner's or one made from the ring at the
//! first seat that asks; a seat's first frame is the screen so far; the
//! model is the pty's size, the least of the seats'; a seat that goes takes
//! its view with it; and no model is made once the shell ended.
//! `tests/serve_share_frames.rs` holds them through russh.

use std::time::Duration;

use tokio::io::{AsyncReadExt, DuplexStream};

use super::super::Shares;
use super::*;
use crate::frames::receiver::Receiver;
use crate::server::frames::FIRST_VIEW;

fn size(cols: u32, rows: u32) -> Size {
    Size { cols, rows, px_width: 0, px_height: 0 }
}

/// A shared shell whose pty takes the keys and the sizes nowhere, with the
/// owner's seat of 80 by 24.
fn shell() -> Arc<Seat> {
    Hub::open(&Shares::default(), Box::new(tokio::io::sink()), Box::new(|_| {}), size(80, 24))
}

/// Read the frames on `from` until `done` holds of what they drew.
async fn until(from: &mut DuplexStream, receiver: &mut Receiver, done: impl Fn(&Receiver) -> bool) {
    let mut buf = vec![0u8; 1 << 16];
    while !done(receiver) {
        // On the paused clock, a frame that never comes fails at once.
        let read = tokio::time::timeout(Duration::from_secs(60), from.read(&mut buf)).await;
        let n = read.expect("a frame within the wait").expect("the pipe");
        assert!(n > 0, "the frames ended first");
        receiver.feed(&buf[..n]).expect("frames of this version");
    }
}

fn shows(needle: &'static str) -> impl Fn(&Receiver) -> bool {
    move |r| r.state().is_some_and(|state| state.screen.contents().contains(needle))
}

/// A seat that asks for frames gets the shell's one model, whose first
/// frame is the screen so far, then the output, then the last frame at the
/// shell's end; after it no model is made. One table: whether the owner
/// asked for frames (its model from the start) or not (a model made from
/// the ring at the seat's ask).
#[tokio::test(start_paused = true)]
async fn a_seat_gets_the_screen_so_far_then_the_output() {
    for owners in [false, true] {
        let owner = shell();
        let hub = owner.hub.clone();
        if owners {
            let frames = Shared::new(size(80, 24), Version::One);
            hub.keep_frames(frames.clone());
            owner.set_framed(frames, FIRST_VIEW);
        }
        hub.said(b"before the seat\r\n");
        let frames = hub.frames_for(Version::One).expect("a shell that runs");
        let again = hub.frames_for(Version::Two).expect("a shell that runs");
        assert!(Arc::ptr_eq(&frames, &again), "owner's {owners}: one model for the shell");
        let view = frames.join(Version::One);
        let (out, mut from) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(frames.clone().run_epoch(view, out, tokio::io::sink(), None::<tokio::io::Sink>));
        let mut receiver = Receiver::default();
        until(&mut from, &mut receiver, shows("before the seat")).await;
        hub.said(b"after the seat");
        until(&mut from, &mut receiver, shows("after the seat")).await;
        hub.end();
        until(&mut from, &mut receiver, Receiver::ended).await;
        tokio::time::timeout(Duration::from_secs(5), task).await.expect("the task ends").unwrap();
        assert!(hub.frames_for(Version::One).is_none(), "owner's {owners}: no model once the shell ended");
    }
}

/// The model is the pty's size, the least of each seat's, and a seat that
/// goes takes its view and its size with it.
#[tokio::test(start_paused = true)]
async fn the_model_is_the_least_size_and_a_seat_takes_its_view_along() {
    let owner = shell();
    let hub = owner.hub.clone();
    let frames = hub.frames_for(Version::One).expect("a shell that runs");
    assert_eq!(frames.seen(), (vec![], (24, 80)), "no view, the owner's size");
    let seat = hub.seat(Some(size(40, 10)));
    let view = frames.join(Version::One);
    seat.set_framed(frames.clone(), view);
    hub.said(b"x");
    assert_eq!(frames.seen(), (vec![view], (10, 40)), "the seat's view, the least size");
    drop(seat);
    hub.said(b"y");
    assert_eq!(frames.seen(), (vec![], (24, 80)), "the seat's view and size went with it");
}
