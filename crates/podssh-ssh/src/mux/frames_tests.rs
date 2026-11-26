//! `--frames` through a control master (T-303): podssh's master and
//! podssh's client on a control socket, over a connection to a russh server
//! in this process that takes or refuses the ask as `podssh serve` and
//! OpenSSH's sshd do. The client's terminal is three pipes; a `vt100` model
//! reads what the master wrote to its output.
//!
//! One table, one rule: the master asks the far end for frames only where
//! the client's entry asked and a pty came; the entry never reaches the far
//! end as a variable; a frame taken is drawn on the client's output and
//! acknowledged; each refusal is one line on the client's stderr, none for
//! a quiet client, and the session shows each byte.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::client::{self, SessionRequest};
use super::master::Persist;
use super::mframes::Ask;
use super::tests::{bounded, control, login_to, Scratch};
use super::{alongside, Mastered};
use crate::frames::screen::Model;
use crate::frames::sender::{Sender, COLLECT, PATIENCE};
use crate::frames::wire::{encode, Version};
use crate::frames::{ACK, ENV, EXT, NO_TERMINAL, REFUSED};

const ROWS: u16 = 24;
const COLS: u16 = 80;
/// What the far end's shell shows: as a frame where it took the ask, else
/// as bytes.
const FRAMED: &str = "FRAMED$ ";
const BYTES: &str = "BYTES$ ";
/// How long the far end waits for the acknowledgement of its frame.
const ACK_WAIT: Duration = Duration::from_secs(10);

/// Each request of `env` that the far end saw, by name and value, in order.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// The far end: a pty or none, and the ask taken (as `podssh serve` takes
/// it) or refused (as OpenSSH's sshd does).
struct Far {
    pty: bool,
    take: bool,
    seen: Seen,
    took: Option<Version>,
    acked: Option<oneshot::Sender<()>>,
    acked_rx: Option<oneshot::Receiver<()>>,
}

impl Far {
    fn new(pty: bool, take: bool, seen: Seen) -> Far {
        let (acked, acked_rx) = oneshot::channel();
        Far { pty, take, seen, took: None, acked: Some(acked), acked_rx: Some(acked_rx) }
    }
}

/// The far end's first frame: the whole screen of `text`, in `version`.
fn frame(version: Version, text: &str) -> Vec<u8> {
    let mut model = Model::new(ROWS, COLS, false).without_lines();
    model.feed(text.as_bytes());
    let mut sender = Sender::default();
    let now = Instant::now();
    sender.changed(now);
    let (head, body) = sender.frame(&model.state(), false, now + PATIENCE + COLLECT).expect("a frame is due");
    encode(version, head, &[], &body)
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        if self.pty {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().push((name.to_string(), value.to_string()));
        if name == ACK {
            if let Some(acked) = self.acked.take() {
                let _ = acked.send(());
            }
            return Ok(());
        }
        if name != ENV {
            return Ok(());
        }
        // The first version that it knows, once, as serve takes it.
        let version = Version::of(value).filter(|_| self.take && self.took.is_none());
        match version {
            Some(version) => {
                self.took = Some(version);
                session.channel_success(channel)
            }
            None => session.channel_failure(channel),
        }
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut ServerSession) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let handle = session.handle();
        let (took, acked) = (self.took, self.acked_rx.take());
        tokio::spawn(async move {
            match (took, acked) {
                (Some(version), Some(acked)) => {
                    let _ = handle.extended_data(channel, EXT, frame(version, FRAMED)).await;
                    let _ = tokio::time::timeout(ACK_WAIT, acked).await;
                }
                _ => {
                    let _ = handle.data(channel, BYTES.as_bytes().to_vec()).await;
                }
            }
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }
}

/// One row: what the far end does, what the client asks, and what the
/// client's terminal and the far end saw.
struct Row {
    name: &'static str,
    pty: bool,
    take: bool,
    ask: Option<Ask>,
    /// The text on the client's screen.
    shows: &'static str,
    /// The line on the client's stderr, if any.
    says: Option<&'static str>,
    /// The values of the asks that the far end saw, in order.
    asks: &'static [&'static str],
    /// The far end got an acknowledgement.
    acked: bool,
}

const ONE: Option<Ask> = Some(Ask { scroll: false, quiet: false });
const SCROLL: Option<Ask> = Some(Ask { scroll: true, quiet: false });
const QUIET: Option<Ask> = Some(Ask { scroll: false, quiet: true });

const ROWS_OF_THE_TABLE: &[Row] = &[
    Row { name: "taken", pty: true, take: true, ask: ONE, shows: FRAMED, says: None, asks: &["v1"], acked: true },
    Row {
        name: "taken, version 2 first",
        pty: true,
        take: true,
        ask: SCROLL,
        shows: FRAMED,
        says: None,
        asks: &["v2", "v1"],
        acked: true,
    },
    Row {
        name: "refused",
        pty: true,
        take: false,
        ask: ONE,
        shows: BYTES,
        says: Some(REFUSED),
        asks: &["v1"],
        acked: false,
    },
    Row {
        name: "refused, quiet",
        pty: true,
        take: false,
        ask: QUIET,
        shows: BYTES,
        says: None,
        asks: &["v1"],
        acked: false,
    },
    Row {
        name: "no pty",
        pty: false,
        take: true,
        ask: ONE,
        shows: BYTES,
        says: Some(NO_TERMINAL),
        asks: &[],
        acked: false,
    },
    Row { name: "not asked", pty: true, take: true, ask: None, shows: BYTES, says: None, asks: &[], acked: false },
];

/// The screen that the client's output shows.
fn screen(bytes: &[u8]) -> String {
    let size = |n: u16| std::num::NonZeroU16::new(n).unwrap();
    let mut model = vt100::Parser::new(size(ROWS), size(COLS), 0);
    model.process(bytes);
    model.screen().contents()
}

#[tokio::test]
async fn a_podssh_master_draws_the_frames_that_its_client_asked_for() {
    for row in ROWS_OF_THE_TABLE {
        bounded(async {
            let scratch = Scratch::new(&format!("frames-{}", row.name.replace([' ', ','], "-")));
            let seen = Seen::default();
            let (handle, log) = login_to(Far::new(row.pty, row.take, seen.clone())).await;
            let path = scratch.socket();
            let work = async {
                let c = client::connect(&path).await.expect("a master");
                assert!(c.offers_frames(), "{}: a podssh master offers frames in its hello", row.name);
                let (stdin_r, stdin_w) = std::io::pipe().unwrap();
                let (mut out_r, out_w) = std::io::pipe().unwrap();
                let (mut err_r, err_w) = std::io::pipe().unwrap();
                let mut env = vec!["LANG=C".to_string()];
                env.extend(row.ask.map(Ask::entry));
                let request = SessionRequest {
                    tty: true,
                    term: "xterm".into(),
                    env,
                    host: "mux.test".into(),
                    ..Default::default()
                };
                let fds = [stdin_r.as_raw_fd(), out_w.as_raw_fd(), err_w.as_raw_fd()];
                assert_eq!(c.session_on(request, fds, &log).await, 0, "{}: the shell's status", row.name);
                drop((stdin_r, stdin_w, out_w, err_w));
                let (mut out, mut err) = (Vec::new(), String::new());
                out_r.read_to_end(&mut out).unwrap();
                err_r.read_to_string(&mut err).unwrap();
                (out, err)
            };
            let (out, err) = match alongside(&handle, Some(control(&scratch, Persist::No, None)), &log, work).await {
                Mastered::Done(both) => both,
                Mastered::Ended(why) => panic!("{}: the master ended the run: {why:?}", row.name),
            };
            let shown = screen(&out);
            assert!(shown.contains(row.shows.trim_end()), "{}: the screen {shown:?}", row.name);
            // A frame is drawn on the output, never written to stderr as
            // the bytes of extended data, which a master before this wrote.
            match row.says {
                Some(line) => assert_eq!(err, format!("podssh: {line}\r\n"), "{}: stderr", row.name),
                None => assert_eq!(err, "", "{}: stderr", row.name),
            }
            let seen = seen.lock().unwrap().clone();
            let asks: Vec<&str> = seen.iter().filter(|(n, _)| n == ENV).map(|(_, v)| v.as_str()).collect();
            assert_eq!(asks, row.asks, "{}: the asks, and no entry passed on as a variable", row.name);
            assert!(seen.iter().any(|(n, v)| n == "LANG" && v == "C"), "{}: the other variables pass", row.name);
            assert_eq!(seen.iter().any(|(n, _)| n == ACK), row.acked, "{}: the acknowledgement", row.name);
        })
        .await;
    }
}
