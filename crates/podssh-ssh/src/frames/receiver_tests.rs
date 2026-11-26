//! The two halves together, with no I/O (T-303): a sender, a receiver,
//! and a terminal that reads what the receiver draws.

use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::frames::screen::Model;
use crate::frames::sender::{Sender, COLLECT, PATIENCE};
use crate::frames::wire::{encode, Head, Version};

const ROWS: u16 = 4;
const COLS: u16 = 20;

/// The far end: its pty's model and its sender, on a clock that each frame
/// moves past every wait.
struct Far {
    model: Model,
    sender: Sender,
    now: Instant,
}

impl Far {
    fn new() -> Far {
        Far { model: Model::new(ROWS, COLS, false), sender: Sender::default(), now: Instant::now() }
    }

    /// The pty wrote `output`: the frame of it, encoded.
    fn frame(&mut self, output: &str) -> Vec<u8> {
        self.model.feed(output.as_bytes());
        self.sender.changed(self.now);
        self.now += PATIENCE + COLLECT;
        let (head, body) = self.sender.frame(&self.model.state(), false, self.now).expect("a frame is due");
        encode(Version::Two, head, &self.model.lines_after(self.sender.since()), &body)
    }

    fn acked(&mut self, ack: Ack) {
        self.now += Duration::from_millis(10);
        self.sender.acked(ack, self.now);
    }
}

/// The client's terminal: a model that reads what the receiver draws.
fn terminal() -> Model {
    Model::new(ROWS, COLS, false)
}

/// Frames in order, each acknowledged: the receiver holds the far end's
/// screen after each, its terminal shows it, the first frame is the whole
/// screen and each later one starts from the one before.
#[test]
fn in_order_each_frame_gives_the_far_ends_screen() {
    let (mut far, mut near, mut term) = (Far::new(), Receiver::default(), terminal());
    assert!(near.leave().is_empty() && near.take_ack().is_none(), "nothing came yet");
    for (n, output) in ["$ ", "ls\r\n", "a  b  c\r\n$ ", "\x1b[2J\x1b[H\x1b[1mvi\x1b[m", "\x1b[?25l"].iter().enumerate()
    {
        let bytes = far.frame(output);
        let full = bytes[1] & 1 != 0;
        assert_eq!(full, n == 0, "only the first frame is the whole screen (frame {n})");
        let drawn = near.feed(&bytes).unwrap();
        assert_eq!(drawn.starts_with(b"\x1b[999;1H"), n == 0, "the screen goes up once (frame {n})");
        term.feed(&drawn);
        let want = far.model.state();
        assert!(near.state().is_some_and(|held| held.same(&want)), "the state held after frame {n}");
        assert!(term.state().same(&want), "the terminal after frame {n}");
        let ack = near.take_ack().expect("an acknowledgement is due");
        assert_eq!(ack, Ack { number: n as u64 + 1, lost: false });
        assert!(near.take_ack().is_none(), "one for each pass");
        far.acked(ack);
    }
    // The end gives the cursor back, which the last frame hid.
    term.feed(&near.leave());
    assert!(!term.state().screen.hide_cursor());
}

/// The frames of one read are drawn once, as the newest state, and
/// acknowledged once.
#[test]
fn the_frames_of_one_read_are_one_draw_and_one_acknowledgement() {
    let (mut far, mut near, mut term) = (Far::new(), Receiver::default(), terminal());
    let mut bytes = Vec::new();
    for output in ["one\r\n", "two\r\n", "three\r\n"] {
        bytes.extend_from_slice(&far.frame(output));
    }
    let drawn = near.feed(&bytes).unwrap();
    assert_eq!(drawn.windows(8).filter(|w| w == b"\x1b[999;1H").count(), 1);
    term.feed(&drawn);
    assert!(term.state().same(&far.model.state()));
    assert_eq!(near.take_ack(), Some(Ack { number: 3, lost: false }));
    assert_eq!(near.take_ack(), None);
    // A read that completes no frame draws nothing, and owes nothing.
    let next = far.frame("four");
    assert!(near.feed(&next[..10]).unwrap().is_empty());
    assert_eq!(near.take_ack(), None);
    term.feed(&near.feed(&next[10..]).unwrap());
    assert!(term.state().same(&far.model.state()));
}

/// A frame whose base the client does not hold is refused and answered
/// so; the far end's next frame is the whole screen, and the client shows
/// it.
#[test]
fn a_frame_with_a_base_that_is_not_held_is_refused_and_then_repaired() {
    let (mut far, mut first, mut term) = (Far::new(), Receiver::default(), terminal());
    for output in ["one\r\n", "two\r\n"] {
        first.feed(&far.frame(output)).unwrap();
        far.acked(first.take_ack().unwrap());
    }
    // A client that holds nothing gets the next frame, which starts from the state 2.
    let mut near = Receiver::default();
    let frame = far.frame("three\r\n");
    assert!(near.feed(&frame).unwrap().is_empty(), "nothing can be drawn");
    let ack = near.take_ack().expect("a refused frame is answered too");
    assert_eq!(ack, Ack { number: 0, lost: true });
    far.acked(ack);
    let frame = far.frame("four");
    assert_eq!(frame[1] & 1, 1, "the whole screen");
    term.feed(&near.feed(&frame).unwrap());
    assert!(term.state().same(&far.model.state()));
    assert_eq!(near.take_ack(), Some(Ack { number: 4, lost: false }));
}

/// A frame that is not newer than the state held is passed over, also a
/// whole screen, and also a second copy; what is owed stays what it was.
/// One table: the frame's number, whether it is a whole screen.
#[test]
fn a_frame_that_is_not_newer_never_moves_the_screen_back() {
    let (mut far, mut near) = (Far::new(), Receiver::default());
    for output in ["one\r\n", "two\r\n", "three\r\n"] {
        near.feed(&far.frame(output)).unwrap();
        far.acked(near.take_ack().unwrap());
    }
    let want = far.model.state();
    let old = Model::new(ROWS, COLS, false).state();
    for (number, full) in [(1u64, true), (2, true), (3, true), (3, false), (2, false)] {
        let base = if full { 0 } else { number - 1 };
        let head = Head { full, bell: true, last: true, number, base, rows: ROWS, cols: COLS, total: 0 };
        let whole = crate::frames::screen::diff(None, &old).0;
        let body: &[u8] = if full { &whole } else { b"x" };
        let drawn = near.feed(&encode(Version::Two, head, &[], body)).unwrap();
        assert!(drawn.is_empty(), "frame {number} (whole: {full}) drew {drawn:?}");
        assert!(near.state().is_some_and(|held| held.same(&want)), "frame {number} moved the state");
        assert!(!near.ended(), "a frame passed over ends nothing");
        assert_eq!(near.take_ack(), Some(Ack { number: 3, lost: false }), "frame {number}");
    }
}

/// After a line of podssh's own, or a new size of the window, the next
/// frame draws the whole screen again; without one it draws the difference.
#[test]
fn a_disturbed_terminal_is_drawn_again_from_its_first_cell() {
    let (mut far, mut near, mut term) = (Far::new(), Receiver::default(), terminal());
    term.feed(&near.feed(&far.frame("one\r\ntwo\r\n")).unwrap());
    far.acked(near.take_ack().unwrap());
    let small = near.feed(&far.frame("x")).unwrap();
    assert!(!small.windows(3).any(|w| w == b"\x1b[J"), "a difference clears nothing: {small:?}");
    term.feed(&small);
    far.acked(near.take_ack().unwrap());
    term.feed(b"\x1b[2;3Hpodssh: a line of its own\r\n");
    near.disturbed();
    let whole = near.feed(&far.frame("y")).unwrap();
    assert!(whole.windows(3).any(|w| w == b"\x1b[J"), "the screen is cleared and drawn: {whole:?}");
    term.feed(&whole);
    assert!(term.state().same(&far.model.state()));
    let after = near.feed(&far.frame("z")).unwrap();
    assert!(!after.windows(3).any(|w| w == b"\x1b[J"), "once: {after:?}");
}

/// A new size at the far end comes as a whole screen of that size, and the
/// terminal is drawn again; the last frame ends the frames; a bell rings
/// once; bytes that are no frame are an error.
#[test]
fn a_new_size_the_last_frame_a_bell_and_bytes_that_are_no_frame() {
    let (mut far, mut near) = (Far::new(), Receiver::default());
    near.feed(&far.frame("one")).unwrap();
    far.acked(near.take_ack().unwrap());
    far.model.resize(ROWS + 3, COLS + 10);
    let frame = far.frame("\r\nwide");
    assert_eq!(frame[1] & 1, 1, "another size: the whole screen");
    let drawn = near.feed(&frame).unwrap();
    assert!(drawn.windows(3).any(|w| w == b"\x1b[J"));
    assert_eq!(near.state().map(State::size), Some((ROWS + 3, COLS + 10)));
    far.acked(near.take_ack().unwrap());

    far.model.feed(b"\x07");
    far.sender.changed(far.now);
    far.now += PATIENCE;
    let (head, body) = far.sender.frame(&far.model.state(), far.model.bell(), far.now).expect("a bell");
    let rung = near.feed(&encode(Version::Two, head, &[], &body)).unwrap();
    assert_eq!(rung, b"\x07", "the bell alone");

    let (head, body) = far.sender.last(&far.model.state(), false, far.now);
    assert!(!near.ended());
    near.feed(&encode(Version::Two, head, &[], &body)).unwrap();
    assert!(near.ended());

    let refused = Receiver::default().feed(b"SSH-2.0-not a frame at all, of any version").unwrap_err();
    assert!(refused.contains("cannot read"), "{refused}");
}
