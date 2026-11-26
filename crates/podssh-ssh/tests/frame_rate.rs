//! The frames of the far end's screen (T-303), with russh's client and
//! podssh's receiver against `podssh serve` and a real pty.
//!
//! The first test is the entry's Prove: through a link in the test of 150
//! ms each way and 64 KiB/s (a round trip of 300 ms), an interactive shell
//! floods its terminal, Ctrl-C goes, and the prompt after it shows on the
//! client's model within three round trips; then the client's model, made
//! of each frame's difference, is the far end's whole screen, cell for
//! cell; and a terminal that read what the client drew holds each line of
//! the flood in its scrollback once, in order, or counted as skipped. The
//! second holds the negotiation: frames come only on a channel with a pty
//! that asked, in place of each byte, in the version asked; each other ask
//! is refused, and its channel carries bytes as before. Where no master
//! opens on this host, each test says that it did not run.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::frames::receiver::Receiver;
use podssh_ssh::frames::screen::State;
use podssh_ssh::frames::wire::Ack;
use podssh_ssh::frames::{ACK, ENV, EXT, VERSION};
use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::{self, pty, Authorized, Settings};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(60);
/// The link of the Prove: each way, and so a round trip of 300 ms.
const DELAY: Duration = Duration::from_millis(150);
const RATE: u64 = 64 * 1024;
/// The bar of the entry: three round trips.
const BAR: Duration = Duration::from_millis(900);
/// The prompt of the far end's shell: set by the command, never typed, so
/// no echo of a typed line is it.
const PROMPT: &str = "FRAMEP>";
const SHELL: &str = "exec env PS1='FRAMEP> ' ENV= /bin/sh -i";
const FLOOD: &[u8] = b"i=0; while :; do i=$((i+1)); echo \"flood $i of a loop that prints for ever\"; done\r";

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn have_pty() -> bool {
    match pty::open() {
        Ok(_) => true,
        Err(why) => {
            eprintln!("did not run: no pty here: {why}");
            false
        }
    }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One way of a link: the bytes leave at `rate` bytes a second, in order,
/// and each arrives `delay` after it left. What waits is bounded by SSH's
/// own windows, as on a road with a deep queue.
async fn one_way(mut from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin, delay: Duration, rate: u64) {
    let (queue, mut queued) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let take = async move {
        let mut buf = vec![0u8; 1024];
        let mut free = Instant::now();
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            free = free.max(Instant::now()) + Duration::from_micros(n as u64 * 1_000_000 / rate);
            if queue.send((free + delay, buf[..n].to_vec())).is_err() {
                return;
            }
        }
    };
    let give = async move {
        while let Some((at, bytes)) = queued.recv().await {
            tokio::time::sleep_until(at).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
    };
    tokio::join!(take, give);
}

/// A logged-in connection to a new server with this host's PATH, through
/// a link of `shape` (the delay each way and the rate) where one is given.
async fn connect(shape: Option<(Duration, u64)>) -> client::Handle<Trusting> {
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = Settings { base_env: Some(vec![("PATH".into(), path)]), ..Settings::default() };
    let (near, far) = match shape {
        None => tokio::io::duplex(1 << 22),
        Some((delay, rate)) => {
            let (near, near_link) = tokio::io::duplex(1 << 16);
            let (far_link, far) = tokio::io::duplex(1 << 16);
            let (near_read, near_write) = tokio::io::split(near_link);
            let (far_read, far_write) = tokio::io::split(far_link);
            tokio::spawn(one_way(near_read, far_write, delay, rate));
            tokio::spawn(one_way(far_read, near_write, delay, rate));
            (near, far)
        }
    };
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// What a channel gave, in the order it came.
#[derive(Default)]
struct Seen {
    /// The data of the channel: none with frames.
    out: Vec<u8>,
    /// The first byte of the frames: their version.
    first: Option<u8>,
    receiver: Receiver,
    /// What the receiver drew, as a client's terminal gets it.
    drawn: Vec<u8>,
    /// The bytes of the frames, as the link carried them.
    framed: usize,
    replies: Vec<bool>,
    /// The order of the end: `frame` for the last frame, `status`.
    order: Vec<&'static str>,
    status: Option<u32>,
    closed: bool,
}

impl Seen {
    fn take(&mut self, message: ChannelMsg) {
        match message {
            ChannelMsg::Data { data } => self.out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext } if ext == EXT => {
                self.first = self.first.or(data.first().copied());
                self.framed += data.len();
                let ended = self.receiver.ended();
                let drawn = self.receiver.feed(&data).expect("frames of this version");
                self.drawn.extend_from_slice(&drawn);
                if self.receiver.ended() && !ended {
                    self.order.push("frame");
                }
            }
            ChannelMsg::ExtendedData { .. } => {}
            ChannelMsg::Success => self.replies.push(true),
            ChannelMsg::Failure => self.replies.push(false),
            ChannelMsg::ExitStatus { exit_status } => {
                self.status = Some(exit_status);
                self.order.push("status");
            }
            ChannelMsg::Close => self.closed = true,
            _ => {}
        }
    }

    fn state(&self) -> Option<&State> {
        self.receiver.state()
    }

    fn text(&self) -> String {
        self.state().map(|state| state.screen.contents()).unwrap_or_default()
    }

    /// The row of the cursor on the client's model, with no trailing blank.
    fn cursor_row(&self) -> String {
        let Some(state) = self.state() else { return String::new() };
        let (row, _) = state.screen.cursor_position();
        let (_, cols) = state.screen.size();
        state.screen.rows(0, cols.get()).nth(usize::from(row)).unwrap_or_default().trim_end().to_string()
    }
}

/// Each row that leaves the top of a terminal's primary screen, as text:
/// the terminal's scrollback.
#[derive(Default)]
struct Kept(Vec<String>);

impl vt100::Callbacks for Kept {
    fn on_scroll(&mut self, row: vt100::capture::RowContents<'_>, alternate_screen: bool) {
        if !alternate_screen {
            let mut text = String::new();
            let _ = row.write_formatted_basic(&mut text, &mut vt100::capture::BasicFormattedCaptureState::new());
            self.0.push(vt100::capture::basic_formatted_to_plain(&text).collect());
        }
    }
}

/// The number of a row of the flood, `flood N of ...`.
fn flood_number(row: &str) -> Option<u64> {
    let rest = row.strip_prefix("flood ")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    rest[digits.len()..].starts_with(" of").then(|| digits.parse().ok()).flatten()
}

/// Each line of the flood that `read` (the scrollback, then the screen)
/// holds comes once and in order, and each gap between two of them is the
/// count of the lines said skipped there. The count of lines of the flood.
fn flood_once(read: &[String]) -> usize {
    let (mut last, mut said, mut seen) = (None::<u64>, 0u64, 0);
    for row in read {
        let skipped = row.strip_prefix("[podssh: ").and_then(|rest| rest.split(' ').next()?.parse::<u64>().ok());
        if let Some(count) = skipped {
            said += count;
        } else if let Some(n) = flood_number(row) {
            if let Some(last) = last {
                assert_eq!(n, last + 1 + said, "flood {n} after flood {last} and {said} said skipped");
            }
            (last, said, seen) = (Some(n), 0, seen + 1);
        }
    }
    seen
}

/// Read until `done` holds, and acknowledge the frames once for each
/// message read, as podssh's own loop does.
async fn read_until(channel: &mut Channel<client::Msg>, seen: &mut Seen, done: impl Fn(&Seen) -> bool) {
    let all = async {
        while !done(seen) {
            let Some(message) = channel.wait().await else { panic!("the channel ended: {:?}", seen.text()) };
            seen.take(message);
            // After the last frame the channel may be gone: the far end needs no word then.
            if let Some(ack) = seen.receiver.take_ack() {
                let _ = channel.set_env(false, ACK, ack.value()).await;
            }
        }
    };
    if tokio::time::timeout(LIMIT, all).await.is_err() {
        panic!("not in time: the screen is {:?}, the replies {:?}", seen.text(), seen.replies);
    }
}

/// Read for `time`, acknowledging as [`read_until`] does.
async fn read_for(channel: &mut Channel<client::Msg>, seen: &mut Seen, time: Duration) {
    let end = Instant::now() + time;
    while let Ok(Some(message)) = tokio::time::timeout_at(end, channel.wait()).await {
        seen.take(message);
        if let Some(ack) = seen.receiver.take_ack() {
            let _ = channel.set_env(false, ACK, ack.value()).await;
        }
    }
}

/// Under a flood through a link of 300 ms and 64 KiB/s, Ctrl-C shows the
/// prompt within three round trips, and the client's screen is the far
/// end's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_a_flood_ctrl_c_shows_the_prompt_within_three_round_trips() {
    if !have_pty() {
        return;
    }
    let handle = connect(Some((DELAY, RATE))).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.exec(true, SHELL).await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 3).await;
    assert_eq!(seen.replies, vec![true, true, true], "the pty, the frames, the shell");
    read_until(&mut channel, &mut seen, |s| s.cursor_row() == PROMPT).await;

    channel.data(FLOOD).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.text().contains("flood 1")).await;
    let before = seen.framed;
    read_for(&mut channel, &mut seen, Duration::from_secs(2)).await;
    // The link carries 64 KiB a second: the frames of a flood are far under it.
    let crossed = seen.framed - before;
    assert!(crossed < 2 * 64 * 1024 / 2, "{crossed} bytes of frames crossed in 2 s of flood");
    assert_ne!(seen.cursor_row(), PROMPT, "the flood still runs: {:?}", seen.text());

    let sent = Instant::now();
    channel.data(&[0x03u8][..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.cursor_row() == PROMPT).await;
    let after = sent.elapsed();
    eprintln!("Ctrl-C to the prompt: {} ms ({:.2} round trips)", after.as_millis(), after.as_secs_f64() / 0.3);
    assert!(after < BAR, "the prompt showed {after:?} after Ctrl-C, over three round trips ({BAR:?})");
    assert!(seen.out.is_empty(), "with frames no byte of the pty comes as data: {} came", seen.out.len());

    // The screen is still now. The client's state was made of each frame's
    // difference; the far end's whole screen, asked for by a client that
    // says it holds nothing, must be the same.
    read_for(&mut channel, &mut seen, Duration::from_secs(1)).await;
    let made = seen.state().expect("a state").clone();
    let newest = seen.receiver.newest();
    channel.set_env(false, ACK, Ack { number: 0, lost: true }.value()).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.receiver.newest() > newest).await;
    let whole = seen.state().expect("a state");
    assert_eq!(whole.screen.contents(), made.screen.contents(), "the text of the screen");
    assert_eq!(whole.screen.cursor_position(), made.screen.cursor_position(), "the cursor");
    assert!(whole.same(&made), "each cell, each attribute and each mode: {:?}", whole.screen.state_diff(&made.screen));
    // What the receiver drew gives a terminal that same screen.
    let cells = |n: u16| std::num::NonZeroU16::new(n).unwrap();
    let mut terminal = vt100::Parser::new_with_callbacks(cells(24), cells(80), 0, Kept::default());
    terminal.process(&seen.drawn);
    assert_eq!(terminal.screen().contents(), whole.screen.contents(), "what a terminal shows of the draws");
    // Its scrollback holds the flood: each line once, or counted.
    let mut read = terminal.callbacks().0.clone();
    read.extend(terminal.screen().rows(0, 80));
    let lines = flood_once(&read);
    assert!(lines > 24, "the flood's lines in the scrollback: {lines}");
    assert_eq!(seen.first, Some(2), "frames of version 2");

    channel.data(&b"exit 7\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.closed).await;
    assert_eq!(seen.status, Some(7));
    assert_eq!(seen.order, vec!["frame", "status"], "the last frame comes before the status");
}

/// Frames come only on a channel with a pty that asked for this version,
/// once: one table of asks. With them, a new size comes as a whole screen
/// of that size, a title and a bell cross, and the last frame comes before
/// the status; without them, the channel's bytes come as data, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frames_come_only_where_they_were_asked_on_a_pty() {
    if !have_pty() {
        return;
    }
    let handle = connect(None).await;

    // Refused asks: before the pty, and another version. The channel then
    // carries each byte, and no frame.
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, "v3").await.unwrap();
    channel.exec(true, "printf ready; read line").await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 4 && s.out.ends_with(b"ready")).await;
    assert_eq!(seen.replies, vec![false, true, false, true], "no pty yet; the pty; v3; the command");
    channel.data(&b"x\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.closed).await;
    assert_eq!((seen.framed, seen.status), (0, Some(0)), "no frame without the ask taken");

    // The ask taken, and a second one refused.
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.set_env(true, ENV, VERSION).await.unwrap();
    channel.exec(true, "printf '\\033]2;a title\\007\\007hello'; read line; exit 3").await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 4 && s.text().contains("hello")).await;
    assert_eq!(seen.replies, vec![true, true, false, true], "the pty; the frames; once; the command");
    assert_eq!(seen.first, Some(2), "frames of version 2");
    assert_eq!(seen.state().and_then(|state| state.title.as_deref()), Some(&b"a title"[..]));
    // One BEL ends the title's sequence; the other is the bell.
    let bells = seen.drawn.iter().filter(|b| **b == 0x07).count();
    assert_eq!(bells, 2, "the bell rings once on the client's terminal");
    assert!(seen.out.is_empty(), "no byte of the pty as data: {:?}", String::from_utf8_lossy(&seen.out));

    channel.window_change(100, 30, 0, 0).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.state().is_some_and(|state| state.size() == (30, 100))).await;
    assert!(seen.text().contains("hello"), "the screen in its new size: {:?}", seen.text());

    channel.data(&b"x\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.closed).await;
    assert_eq!(seen.status, Some(3));
    assert_eq!(seen.order, vec!["frame", "status"], "the last frame comes before the status");
    assert!(seen.out.is_empty(), "no byte of the pty as data to the end");

    // An older client asks v1 alone, and gets frames of version 1.
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.set_env(true, ENV, "v1").await.unwrap();
    channel.exec(true, "printf hello; read line").await.unwrap();
    let mut seen = Seen::default();
    read_until(&mut channel, &mut seen, |s| s.replies.len() == 3 && s.text().contains("hello")).await;
    assert_eq!((seen.replies.clone(), seen.first), (vec![true, true, true], Some(1)), "version 1");
    channel.data(&b"x\r"[..]).await.unwrap();
    read_until(&mut channel, &mut seen, |s| s.closed).await;
    assert_eq!(seen.status, Some(0));
}
