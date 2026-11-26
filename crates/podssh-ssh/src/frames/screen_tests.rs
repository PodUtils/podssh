//! The difference of two screens, on one table of screens (T-303): each
//! pair is a base and a new state, and each rule holds for each pair.

use super::*;

const ROWS: u16 = 6;
const COLS: u16 = 20;

/// The screens: what each one is, and the output of a pty that draws it.
fn screens() -> Vec<(&'static str, Vec<u8>)> {
    let lines: String = (1..=40).map(|n| format!("line {n}\r\n")).collect();
    let table: Vec<(&'static str, String)> = vec![
        ("an empty screen", String::new()),
        ("a word", "hello".into()),
        ("two rows", "hello\r\nworld".into()),
        ("colours and attributes", "\x1b[31mred\x1b[0m plain \x1b[1;4mbold\x1b[m \x1b[7mrev".into()),
        ("more lines than rows", lines),
        ("the cursor moved", "\x1b[5;10Hx\x1b[2;3Hy".into()),
        ("wide and accented characters", "\u{4e16}\u{754c} caf\u{e9}".into()),
        ("a line that wraps", "a".repeat(50)),
        ("a row filled to its last column", "b".repeat(usize::from(COLS))),
        ("the alternate screen", "primary\x1b[?1049h\x1b[2J\x1b[Halt screen".into()),
        ("back from the alternate screen", "primary\x1b[?1049halt\x1b[?1049l".into()),
        ("the modes of the keys", "\x1b[?1h\x1b=\x1b[?2004h\x1b[?25lkeys".into()),
        ("the mouse", "\x1b[?1000h\x1b[?1006hmouse".into()),
        ("a title", "\x1b]2;my title\x07text".into()),
        ("erased parts", "abc\rdef\x1b[K\x1b[2;1Hxyz\x1b[1;2H\x1b[K".into()),
        ("a full screen of one letter", "y\r\n".repeat(30)),
    ];
    table.into_iter().map(|(what, bytes)| (what, bytes.into_bytes())).collect()
}

fn state_of(bytes: &[u8]) -> State {
    let mut model = Model::new(ROWS, COLS, false);
    model.feed(bytes);
    model.state()
}

/// What a person sees of `state`, read with no difference of `vt100`: the
/// text, the cursor, whether it shows, the modes of the keys, the title.
fn seen(state: &State) -> (String, (u16, u16), bool, String, Option<Vec<u8>>) {
    let screen = &state.screen;
    (
        screen.contents(),
        screen.cursor_position(),
        screen.hide_cursor(),
        screen.input_mode_formatted(),
        state.title.as_deref().map(<[u8]>::to_vec),
    )
}

/// The state that a terminal shows after `base` then `new` of one stream:
/// `new`, with the window's title of `base` when `new` set none, as a
/// terminal has no sequence that takes a title away. Two screens of the table
/// can pair so; one stream never goes from a title to none.
fn after(base: &State, new: &State) -> State {
    let mut want = new.clone();
    if want.title.is_none() {
        want.title = base.title.clone();
    }
    want
}

fn assert_shows(got: &State, want: &State, what: &str) {
    assert_eq!(seen(got), seen(want), "{what}");
    assert!(got.screen.state_diff(&want.screen).is_empty(), "{what}: {:?}", got.screen.state_diff(&want.screen));
    assert!(want.screen.state_diff(&got.screen).is_empty(), "{what}: {:?}", want.screen.state_diff(&got.screen));
}

/// A frame's body turns its base into its state, for each pair of the
/// table; a body with no base draws the whole screen; and a screen that did
/// not change has an empty body, so no frame goes for it.
#[test]
fn a_body_turns_each_base_into_each_state() {
    let screens = screens();
    for (new_name, new_bytes) in &screens {
        let new = state_of(new_bytes);
        let (body, full) = diff(None, &new);
        assert!(full, "{new_name}: no base");
        assert_shows(&apply(None, ROWS, COLS, &body), &new, &format!("{new_name}, whole"));
        for (base_name, base_bytes) in &screens {
            let base = state_of(base_bytes);
            let (body, full) = diff(Some(&base), &new);
            assert!(!full, "{base_name} to {new_name}: a base of the same size");
            if base_name == new_name {
                assert!(body.is_empty(), "{new_name} to itself: {:?}", String::from_utf8_lossy(&body));
                assert!(base.same(&new), "{new_name} is itself");
            }
            // The client's base is itself made of frames, never of the pty's bytes.
            let held = apply(None, ROWS, COLS, &diff(None, &base).0);
            let got = apply(Some(&held), ROWS, COLS, &body);
            assert_shows(&got, &after(&base, &new), &format!("{base_name} to {new_name}"));
        }
    }
}

/// What the client writes to its terminal turns a terminal that shows one
/// state into one that shows the next, for each pair; a repaint does it
/// from a terminal whose content and cursor are anything.
#[test]
fn what_is_drawn_turns_a_terminal_into_the_next_state() {
    let screens = screens();
    let terminal = |bytes: &[&[u8]]| {
        let mut model = Model::new(ROWS, COLS, false);
        bytes.iter().for_each(|part| model.feed(part));
        model.state()
    };
    for (new_name, new_bytes) in &screens {
        let new = state_of(new_bytes);
        let first = draw(None, &new, false);
        assert_shows(&terminal(&[first.as_slice()]), &new, &format!("{new_name}, the first draw"));
        for (base_name, base_bytes) in &screens {
            let base = state_of(base_bytes);
            let shown = draw(None, &base, false);
            let next = draw(Some(&base), &new, false);
            assert_shows(
                &terminal(&[shown.as_slice(), next.as_slice()]),
                &after(&base, &new),
                &format!("{base_name} to {new_name}, drawn"),
            );
            // A line of podssh's own moved the cursor and wrote over a row.
            let again = draw(Some(&base), &new, true);
            let noise: &[u8] = b"\x1b[3;4Hpodssh: a line of its own\r\n";
            assert_shows(
                &terminal(&[shown.as_slice(), noise, again.as_slice()]),
                &after(&base, &new),
                &format!("{base_name} to {new_name}, repainted"),
            );
        }
    }
}

/// A base of another size is no base: the body draws the whole screen.
#[test]
fn a_base_of_another_size_gives_the_whole_screen() {
    let base = state_of(b"hello");
    let mut model = Model::new(ROWS, COLS, false);
    model.feed(b"hello");
    model.resize(ROWS + 2, COLS + 5);
    model.feed(b"\r\nmore");
    let new = model.state();
    let (body, full) = diff(Some(&base), &new);
    assert!(full);
    assert_eq!(new.size(), (ROWS + 2, COLS + 5));
    assert_shows(&apply(None, ROWS + 2, COLS + 5, &body), &new, "after a new size");
    assert!(!base.same(&new));
}

/// The end gives the terminal back: each mode of the keys off, the cursor
/// shown; a screen with none of them changed gets the attributes' reset
/// alone.
#[test]
fn the_end_takes_each_mode_of_the_keys_off() {
    let busy = state_of(b"\x1b[?1h\x1b=\x1b[?2004h\x1b[?1000h\x1b[?25l\x1b[1mx");
    let mut model = Model::new(ROWS, COLS, false);
    model.feed(&draw(None, &busy, false));
    assert!(model.state().screen.hide_cursor() && model.state().screen.application_cursor());
    model.feed(&leave(&busy));
    let after = model.state().screen;
    let plain = Model::new(ROWS, COLS, false).state().screen;
    assert_eq!(after.input_mode_formatted(), plain.input_mode_formatted());
    assert!(!after.hide_cursor() && !after.bold());
    assert_eq!(leave(&state_of(b"plain")), b"\x1b[m");
}

/// The far end's model answers the questions that a program waits on, and
/// no other; the client's model answers none. One table: the question and
/// its answer.
#[test]
fn the_far_end_answers_the_questions_of_a_program() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("the cursor's place", b"ab\x1b[6n", b"\x1b[1;3R"),
        ("the cursor's place on a later row", b"\x1b[4;7H\x1b[6n", b"\x1b[4;7R"),
        ("the cursor past the last column", b"bbbbbbbbbbbbbbbbbbbb\x1b[6n", b"\x1b[1;20R"),
        ("the device's status", b"\x1b[5n", b"\x1b[0n"),
        ("the device's attributes", b"\x1b[c", b"\x1b[?1;2c"),
        ("the device's attributes, with a 0", b"\x1b[0c", b"\x1b[?1;2c"),
        ("the secondary attributes, not answered", b"\x1b[>c", b""),
        ("a private question, not answered", b"\x1b[?6n", b""),
        ("another status, not answered", b"\x1b[7n", b""),
    ];
    for (what, asked, answer) in cases {
        let mut far = Model::new(ROWS, COLS, true);
        far.feed(asked);
        assert_eq!(far.answers_wait(), !answer.is_empty(), "{what}");
        assert_eq!(far.take_answers(), *answer, "{what}");
        assert!(far.take_answers().is_empty(), "{what}: taken once");
        let mut near = Model::new(ROWS, COLS, false);
        near.feed(asked);
        assert!(near.take_answers().is_empty(), "{what}: the client's model answers nothing");
    }
    // A program that asks for ever fills no memory.
    let mut far = Model::new(ROWS, COLS, true);
    far.feed(&b"\x1b[6n".repeat(10_000));
    assert!(far.take_answers().len() <= ANSWERS_MOST);
}

/// A bell waits for the next frame, once; a title is kept with no control
/// byte and no more than its most.
#[test]
fn a_bell_and_a_title_are_kept_beside_the_grid() {
    let mut model = Model::new(ROWS, COLS, false);
    assert!(!model.bell());
    model.feed(b"\x07\x07");
    assert!(model.bell());
    model.clear_bell();
    assert!(!model.bell());
    model.feed(b"\x1b]0;both names\x07");
    assert_eq!(model.state().title.as_deref(), Some(&b"both names"[..]));
    let long = [b"\x1b]2;".as_slice(), "t".repeat(TITLE_MOST + 50).as_bytes(), b"\x1b\\"].concat();
    model.feed(&long);
    assert_eq!(model.state().title.map(|t| t.len()), Some(TITLE_MOST));
    // The title rides a frame's body, and a body with no change of it names none.
    let titled = model.state();
    let (body, _) = diff(None, &titled);
    assert!(body.starts_with(b"\x1b]2;"));
    assert_eq!(apply(None, ROWS, COLS, &body).title, titled.title);
    assert!(diff(Some(&titled), &titled).0.is_empty());
}
