//! Frames from a shell shared by name (T-303 with T-837), with russh's
//! client over pipes in memory and podssh's receiver of the frames: the
//! shell has one model of its screen, and each seat that asked has a view
//! of its own. A watcher and a writer that ask get the screen so far as
//! their first frame, then the output as frames and no byte of it, each
//! with its own base: the writer's client acknowledges and gets differences,
//! the watcher's never does and gets whole screens; the owner, with bytes,
//! reads the output as before. An owner that asks gets frames, its view
//! answers the program's question on the pty, and a seat of bytes gets the
//! output; at the shell's end each seat with frames gets the last frame,
//! then its status. A name's ask with no pty is refused. Each case needs a
//! pty; a host with none says so.

#![cfg(unix)]

mod share_harness;

use std::time::Duration;

use podssh_ssh::frames::receiver::Receiver;
use podssh_ssh::frames::wire::{Decoder, Head};
use podssh_ssh::frames::{ACK, ENV};
use podssh_ssh::russh::keys::PrivateKey;
use share_harness::{have_pty, key, owner, Seat, Server, LIMIT};

/// The ask of frames of version 1, as `podssh ssh --frames` sends it.
const FRAMES: (&str, &str) = (ENV, "v1");

/// What the frames of one channel drew, read as podssh's client reads them,
/// each frame acknowledged where `acks`.
struct Framed {
    receiver: Receiver,
    read: usize,
    acks: bool,
}

impl Framed {
    fn new(acks: bool) -> Framed {
        Framed { receiver: Receiver::default(), read: 0, acks }
    }

    /// Read the frames of `seat` until the screen that they draw holds
    /// `needle` (or, with "", until the far end's last frame).
    async fn until(&mut self, seat: &Seat, needle: &str) -> String {
        let end = tokio::time::Instant::now() + LIMIT;
        loop {
            let fresh = seat.seen.lock().unwrap().frames[self.read..].to_vec();
            self.read += fresh.len();
            self.receiver.feed(&fresh).expect("frames of this version");
            let ack = self.receiver.take_ack();
            if let Some(ack) = ack.filter(|_| self.acks) {
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

/// The header of each frame that `seat` got.
fn heads(seat: &Seat) -> Vec<Head> {
    let frames = seat.seen.lock().unwrap().frames.clone();
    Decoder::default().feed(&frames).expect("frames").into_iter().map(|frame| frame.head).collect()
}

/// A login under `user` (with `login`) on a pty of 80 by 24, its `asks`,
/// then the shell; each reply.
async fn shell(server: &Server, user: &str, login: &PrivateKey, asks: &[(&str, &str)]) -> Seat {
    let handle = server.login(user, login).await.expect("the login is let in");
    let seat = Seat::open(handle).await;
    seat.write.request_pty(true, "vt100", 80, 24, 0, 0, &[]).await.unwrap();
    for (name, value) in asks {
        seat.write.set_env(true, *name, *value).await.unwrap();
    }
    seat.write.request_shell(true).await.unwrap();
    seat.until("each reply", |seen| seen.replies.len() > asks.len() + 1).await;
    seat
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watcher_and_a_writer_each_get_frames_of_their_own() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let (owner, write, read) = owner(&server).await;
    owner.send(b"echo BEFORE_$((1+2))_END\r").await;
    owner.reads("BEFORE_3_END").await;
    let watcher = shell(&server, &read, &key(), &[FRAMES]).await;
    let writer = shell(&server, &write, &key(), &[FRAMES]).await;
    for seat in [&watcher, &writer] {
        assert_eq!(seat.seen.lock().unwrap().replies, vec![true, true, true], "the pty, the frames, the shell");
    }
    let (mut watched, mut typed) = (Framed::new(false), Framed::new(true));
    // The screen so far is each seat's first frame.
    watched.until(&watcher, "BEFORE_3_END").await;
    typed.until(&writer, "BEFORE_3_END").await;
    for n in 1..=3 {
        writer.send(format!("echo STEP_$(({n}*7))_END\r").as_bytes()).await;
        let shown = format!("STEP_{}_END", n * 7);
        typed.until(&writer, &shown).await;
        watched.until(&watcher, &shown).await;
        owner.reads(&shown).await;
    }
    for seat in [&watcher, &writer] {
        assert!(seat.seen.lock().unwrap().out.is_empty(), "a seat with frames gets no byte of the output");
    }
    assert!(owner.seen.lock().unwrap().frames.is_empty(), "the owner of bytes gets no frame");
    let (quiet, keen) = (heads(&watcher), heads(&writer));
    assert!(quiet.iter().all(|head| head.base == 0), "no acknowledgement, so whole screens: {quiet:?}");
    assert!(keen.iter().any(|head| head.base != 0), "differences from the base acknowledged: {keen:?}");

    // The end: each seat with frames gets its last frame, then the status.
    owner.send(b"exit 0\r").await;
    for (seat, framed) in [(&watcher, &mut watched), (&writer, &mut typed)] {
        seat.until("the shell's end", |seen| seen.closed).await;
        framed.until(seat, "").await;
        assert_eq!(seat.seen.lock().unwrap().status, Some(0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_with_frames_answers_the_program_and_a_seat_of_bytes_reads_on() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let owner = shell(&server, "owner", &server.owner, &[FRAMES]).await;
    assert_eq!(owner.seen.lock().unwrap().replies, vec![true, true, true], "the pty, the frames, the shell");
    owner.until("the names", |seen| String::from_utf8_lossy(&seen.err).contains("watches it")).await;
    let err = String::from_utf8_lossy(&owner.seen.lock().unwrap().err).into_owned();
    let write = err.split_whitespace().find(|word| word.starts_with("rw-")).expect("the name that types").to_string();
    let mut drawn = Framed::new(true);
    let typist = shell(&server, &write, &key(), &[]).await;
    typist.send(b"echo TYPED_$((5*5))_END\r").await;
    typist.reads("TYPED_25_END").await;
    drawn.until(&owner, "TYPED_25_END").await;

    // The program asks the cursor's place: the owner's view answers on the
    // pty, as its terminal would; the seat of bytes, russh's client here,
    // answers nothing. Without the answer `dd` would wait for ever.
    let ask = "stty raw -echo min 0 time 50; printf '\\033[6n'; dd bs=64 count=1 2>/dev/null | od -An -tx1 | \
               head -n 1 | tr -s ' ' | sed 's/^ */ANSWER /'; stty sane\r";
    owner.send(ask.as_bytes()).await;
    let screen = drawn.until(&owner, "ANSWER 1b 5b").await;
    assert!(screen.contains("ANSWER 1b 5b"), "the answer starts with CSI: {screen:?}");

    assert!(owner.seen.lock().unwrap().out.is_empty(), "the owner with frames gets no byte of the output");
    assert!(typist.seen.lock().unwrap().frames.is_empty(), "a seat of bytes gets no frame");
    owner.send(b"exit 3\r").await;
    owner.until("the shell's end", |seen| seen.closed).await;
    drawn.until(&owner, "").await;
    assert_eq!(owner.seen.lock().unwrap().status, Some(3));
    typist.until("the shell's end", |seen| seen.closed).await;
    assert_eq!(typist.seen.lock().unwrap().status, Some(0));
}

/// Who may ask for frames on a shared shell: a name's seat with a pty, of
/// either right; a name's channel with no pty is refused, as frames need
/// one. One table: the name's right, whether it asked for a pty, the reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_asks_for_frames_on_a_seat_with_a_pty() {
    if !have_pty() {
        return;
    }
    let server = Server::new(true);
    let (_owner, write, read) = owner(&server).await;
    let cases = [
        ("a watcher with a pty", &read, true, true),
        ("a writer with a pty", &write, true, true),
        ("a watcher with no pty", &read, false, false),
        ("a writer with no pty", &write, false, false),
    ];
    for (name, user, pty, taken) in cases {
        let seat = Seat::open(server.login(user, &key()).await.expect("the name lets in")).await;
        if pty {
            seat.write.request_pty(true, "vt100", 80, 24, 0, 0, &[]).await.unwrap();
        }
        seat.write.set_env(true, ENV, "v1").await.unwrap();
        let replies = usize::from(pty) + 1;
        seat.until("each reply", |seen| seen.replies.len() >= replies).await;
        assert_eq!(seat.seen.lock().unwrap().replies.last(), Some(&taken), "{name}");
    }
}
