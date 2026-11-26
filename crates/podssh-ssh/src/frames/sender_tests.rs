//! The pace of the frames and their bases (T-303), on a clock of the test.

use super::*;
use crate::frames::screen::Model;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A screen that shows `text`.
fn screen(text: &str) -> State {
    let mut model = Model::new(4, 20, false);
    model.feed(text.as_bytes());
    model.state()
}

fn ack(number: u64) -> Ack {
    Ack { number, lost: false }
}

/// The time from one frame to the next is half the round trip, within its
/// two ends: one table of round trips.
#[test]
fn the_pace_is_half_the_round_trip_within_its_ends() {
    let cases: &[(u64, u64)] = &[(0, 20), (10, 20), (40, 20), (60, 30), (300, 150), (500, 250), (2000, 250)];
    assert_eq!(Sender::default().interval(), LONGEST, "before a round trip is measured");
    for (trip, pace) in cases {
        let start = Instant::now();
        let mut sender = Sender::default();
        sender.changed(start);
        let (head, _) = sender.frame(&screen("a"), false, start + COLLECT).expect("the first frame");
        sender.acked(ack(head.number), start + COLLECT + ms(*trip));
        assert_eq!(sender.round_trip(), Some(ms(*trip)), "the first sample is the round trip");
        assert_eq!(sender.interval(), ms(*pace), "a round trip of {trip} ms");
    }
}

/// A frame waits for the collection after the first change, and for the
/// pace after the frame before; with nothing changed, none is due.
#[test]
fn a_frame_waits_for_the_collection_and_for_the_pace() {
    let start = Instant::now();
    let mut sender = Sender::default();
    assert_eq!(sender.due(), None, "nothing changed");
    assert!(sender.changed(start), "the first change");
    assert!(!sender.changed(start + ms(3)), "a later one moves nothing");
    assert_eq!(sender.due(), Some(start + COLLECT));
    assert!(sender.frame(&screen("a"), false, start + ms(7)).is_none(), "sooner than the collection");
    let (first, body) = sender.frame(&screen("a"), false, start + COLLECT).expect("the first frame");
    assert!(first.full && first.number == 1 && first.base == 0 && !body.is_empty(), "{first:?}");
    assert_eq!((first.rows, first.cols), (4, 20));
    assert_eq!(sender.due(), None, "nothing changed since the frame");
    // A round trip of 300 ms: the next frame goes 150 ms after the last.
    let sent = start + COLLECT;
    sender.acked(ack(1), sent + ms(300));
    sender.changed(sent + ms(10));
    assert_eq!(sender.due(), Some(sent + ms(150)));
    assert!(sender.frame(&screen("ab"), false, sent + ms(149)).is_none());
    let (second, _) = sender.frame(&screen("ab"), false, sent + ms(150)).expect("the second frame");
    assert!(!second.full && second.number == 2 && second.base == 1, "{second:?}");
}

/// A screen that is what the client will show makes no frame; a bell makes
/// one with an empty body; a screen that went back to the base while a
/// later frame is on its way makes one, as the client shows the later one.
#[test]
fn a_frame_goes_only_where_the_client_would_differ() {
    let start = Instant::now();
    let mut sender = Sender::default();
    sender.changed(start);
    sender.frame(&screen("a"), false, start + COLLECT).expect("the first frame");
    sender.acked(ack(1), start + ms(20));
    let mut now = start + ms(1000);
    sender.changed(now);
    assert!(sender.frame(&screen("a"), false, now + COLLECT).is_none(), "the same screen: a flood of one line");
    assert_eq!(sender.due(), None);
    sender.changed(now);
    let (rung, body) = sender.frame(&screen("a"), true, now + COLLECT).expect("a bell");
    assert!(rung.bell && body.is_empty() && rung.base == 1, "{rung:?}");
    sender.acked(ack(rung.number), now + ms(20));
    now += ms(1000);
    sender.changed(now);
    let (later, _) = sender.frame(&screen("ab"), false, now + COLLECT).expect("a change");
    now += ms(1000);
    sender.changed(now);
    let (back, body) = sender.frame(&screen("a"), false, now + COLLECT).expect("back to the base's screen");
    let base = rung.number;
    assert_eq!((later.base, back.base, body.is_empty()), (base, base, true), "from the base, to the base's screen");
}

/// While WINDOW frames wait for an acknowledgement no frame goes, however
/// much changes; an acknowledgement lets the next go at the pace, and
/// with none the next goes after PATIENCE.
#[test]
fn no_frame_goes_while_the_window_waits() {
    let start = Instant::now();
    let mut sender = Sender::default();
    let mut now = start;
    for n in 0..WINDOW {
        sender.changed(now);
        now += LONGEST + COLLECT;
        sender.frame(&screen(&format!("frame {n}")), false, now).expect("within the window");
    }
    assert_eq!(sender.waiting(), WINDOW);
    let last = now;
    sender.changed(now);
    assert_eq!(sender.due(), Some(last + PATIENCE));
    assert!(sender.frame(&screen("flood"), false, last + LONGEST * 3).is_none(), "the window is full");
    // An acknowledgement of the first opens it.
    sender.acked(ack(1), last + ms(100));
    let due = sender.due().expect("a change waits");
    assert!(due < last + PATIENCE && due <= last + LONGEST, "at the pace again: {:?}", due - last);
    let (next, _) = sender.frame(&screen("flood"), false, due).expect("the window opened");
    assert_eq!((next.number, next.base, next.full), (WINDOW as u64 + 1, 1, false));
}

/// With no acknowledgement at all, a frame goes each PATIENCE, the states
/// kept stay at HELD, and an acknowledgement of a state that is gone moves
/// no base.
#[test]
fn a_client_that_never_acknowledges_costs_a_bounded_memory() {
    let start = Instant::now();
    let mut sender = Sender::default();
    let mut now = start;
    for n in 0..20u64 {
        sender.changed(now);
        now += PATIENCE + COLLECT;
        let (head, _) = sender.frame(&screen(&format!("frame {n}")), false, now).expect("after the patience");
        assert!(head.full && head.base == 0, "no base was acknowledged: {head:?}");
        assert!(sender.waiting() <= HELD, "{} states kept", sender.waiting());
    }
    sender.acked(ack(2), now);
    sender.changed(now);
    now += PATIENCE + COLLECT;
    let (head, _) = sender.frame(&screen("after"), false, now).expect("a frame");
    assert!(head.full, "the state 2 is gone, so it is no base: {head:?}");
    sender.acked(ack(head.number), now);
    sender.changed(now);
    let (next, _) = sender.frame(&screen("after that"), false, now + LONGEST).expect("a frame");
    assert_eq!((next.full, next.base), (false, head.number), "a state that is kept is the base");
}

/// A client that lost its base: where the far end keeps the state that the
/// client holds, the next frame starts from it; else it is the whole screen.
/// One table: what the client says it holds, and the next frame's base.
#[test]
fn a_client_that_lost_its_base_gets_a_frame_that_it_can_draw() {
    // Each case starts with the state 1 acknowledged, and 2 and 3 sent.
    let cases: &[(&str, u64, Option<u64>)] = &[
        ("it holds the base", 1, Some(1)),
        ("it holds a state sent later", 2, Some(2)),
        ("it holds a state that the far end never sent", 9, None),
        ("it holds nothing", 0, None),
    ];
    for (what, holds, base) in cases {
        let start = Instant::now();
        let mut sender = Sender::default();
        sender.changed(start);
        sender.frame(&screen("one"), false, start + COLLECT).expect("the frame 1");
        sender.acked(ack(1), start + ms(20));
        let mut now = start;
        for text in ["two", "three"] {
            now += ms(1000);
            sender.changed(now);
            sender.frame(&screen(text), false, now + COLLECT).expect("a frame");
        }
        now += ms(1000);
        sender.acked(Ack { number: *holds, lost: true }, now);
        assert_eq!(sender.waiting(), 0, "{what}: the frames after it are forgotten");
        // The screen did not change since the frame 3, and a frame goes all the same.
        let due = sender.due().expect("a frame goes again");
        let (head, _) = sender.frame(&screen("three"), false, due).expect("a frame goes again");
        assert_eq!((head.full, head.base), (base.is_none(), base.unwrap_or(0)), "{what}: {head:?}");
    }
}

/// The last frame is the whole screen, marked, whatever was acknowledged.
#[test]
fn the_last_frame_is_the_whole_screen() {
    let start = Instant::now();
    let mut sender = Sender::default();
    sender.changed(start);
    sender.frame(&screen("a"), false, start + COLLECT).expect("the first frame");
    sender.acked(ack(1), start + ms(20));
    let (head, body) = sender.last(&screen("the end"), true, start + ms(30));
    assert!(head.last && head.full && head.bell && head.base == 0 && head.number == 2, "{head:?}");
    assert!(String::from_utf8_lossy(&body).contains("the end"));
}

/// Lines alone (a flood that only scrolls, the screen the same) make a
/// frame only while no frame waits for an acknowledgement, and that frame
/// sets no pace: the first frame after a change of the screen goes at
/// once, never behind lines.
#[test]
fn lines_alone_wait_for_an_empty_window_and_never_hold_a_change() {
    let start = Instant::now();
    let (mut model, mut sender) = (Model::new(4, 20, false), Sender::default());
    let flood = |model: &mut Model, lines: usize| model.feed("y\r\n".repeat(lines).as_bytes());
    flood(&mut model, 10);
    sender.changed(start);
    let (first, _) = sender.frame(&model.state(), false, start + COLLECT).expect("the first frame");
    sender.acked(ack(first.number), start + ms(300));

    // Lines alone into an empty window: a frame goes.
    flood(&mut model, 5);
    sender.changed(start + ms(1000));
    let at = sender.due().expect("lines are a change");
    let (lines, _) = sender.frame(&model.state(), false, at).expect("lines alone, the window empty");
    assert!(lines.total > first.total && sender.waiting() == 1, "{lines:?}");

    // More lines while that frame waits: none goes, however late, and
    // nothing is due until the acknowledgement.
    flood(&mut model, 5);
    sender.changed(at + ms(5));
    assert!(sender.frame(&model.state(), false, at + PATIENCE * 3).is_none(), "lines wait for the window");
    assert_eq!(sender.due(), None, "no wait that wakes for nothing");
    let acked = at + ms(300);
    sender.acked(ack(lines.number), acked);
    assert_eq!(sender.due(), Some(acked + COLLECT), "the acknowledgement looks again, at once");
    let (again, _) = sender.frame(&model.state(), false, acked + COLLECT).expect("the lines that waited");
    assert!(again.total > lines.total, "{again:?}");

    // A change of the screen, 20 ms after a frame of lines that waits for
    // its acknowledgement: it goes after the collection, not after the pace.
    model.feed(b"^C\r\n$ ");
    let changed = acked + COLLECT + ms(20);
    sender.changed(changed);
    assert_eq!(sender.due(), Some(changed + COLLECT), "lines set no pace");
    let (prompt, body) = sender.frame(&model.state(), false, changed + COLLECT).expect("the change goes at once");
    assert!(prompt.number == again.number + 1 && !body.is_empty(), "{prompt:?}");
    assert_eq!(sender.waiting(), 2);
}
