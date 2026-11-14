//! The discipline's task of a child whose tty the supervisor answers
//! (T-776): pod-term's termios mode between the client and the child's
//! socket, in the state that the child set. The client's keys go through
//! it to the child, the echo and the signals come out of it; the child's
//! output goes through its `OPOST` to the client, held while the output is
//! stopped. The task ends with the child's output, which stops some time
//! after the child exited, as the pipes' pumps do.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pod_term::termios::Event;
use pod_term::window::Size;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::super::child::{turned, AFTER_EXIT, QUIET};
use super::supervisor::{Shared, Told};

/// The lines that may wait for the child to read them.
const LINES: usize = 128;

/// The ends of the task.
pub struct Ends<K, R, W, S> {
    pub keys: K,
    pub from_child: R,
    pub to_child: W,
    pub screen: S,
}

/// What the task holds while it runs.
struct State {
    shared: Arc<Mutex<Shared>>,
    stopped: bool,
    held: Vec<u8>,
    lines: Option<mpsc::Sender<Vec<u8>>>,
}

impl State {
    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Carry out the tty's events; false once the screen is gone.
    async fn act(&mut self, events: Vec<Event>, screen: &mut (impl AsyncWrite + Unpin)) -> bool {
        for event in events {
            match event {
                Event::ToChild(bytes) => {
                    if bytes.is_empty() {
                        // VEOF on an empty line: a read of 0 bytes, which a
                        // socket gives only at its end, so input ends here.
                        self.lines = None;
                    } else if let Some(lines) = &self.lines {
                        if lines.send(bytes).await.is_err() {
                            self.lines = None;
                        }
                    }
                }
                Event::ToUser(bytes) => {
                    if !self.show(&bytes, screen).await {
                        return false;
                    }
                }
                Event::Signal { sig, flush } => {
                    if flush {
                        self.held.clear();
                    }
                    let fg = self.lock().fg;
                    if fg > 0 {
                        // SAFETY: kill has no memory effect; an ended group is ESRCH.
                        unsafe { libc::kill(-fg, sig.number()) };
                    }
                }
                Event::StopOutput => self.stopped = true,
                Event::StartOutput => {
                    if !self.start(screen).await {
                        return false;
                    }
                }
            }
        }
        true
    }

    async fn show(&mut self, bytes: &[u8], screen: &mut (impl AsyncWrite + Unpin)) -> bool {
        if self.stopped {
            self.held.extend_from_slice(bytes);
            return true;
        }
        screen.write_all(bytes).await.is_ok()
    }

    async fn start(&mut self, screen: &mut (impl AsyncWrite + Unpin)) -> bool {
        self.stopped = false;
        let held = std::mem::take(&mut self.held);
        held.is_empty() || screen.write_all(&held).await.is_ok()
    }
}

/// Run the discipline until the child's output ends, or the screen does.
pub async fn run<K, R, W, S>(
    shared: Arc<Mutex<Shared>>,
    mut told: mpsc::UnboundedReceiver<Told>,
    ends: Ends<K, R, W, S>,
    mut size: watch::Receiver<Size>,
    mut exited: watch::Receiver<bool>,
    stop: Arc<AtomicBool>,
) where
    K: AsyncRead + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    S: AsyncWrite + Unpin,
{
    let Ends { mut keys, mut from_child, to_child, mut screen } = ends;
    let mut state = State { shared, stopped: false, held: Vec::new(), lines: Some(feed(to_child)) };
    let (mut keys_open, mut size_open, mut told_open) = (true, true, true);
    let (mut a, mut b) = (vec![0u8; 4096], vec![0u8; 32 * 1024]);
    // After the child exited: its output until a quiet spell, or a bound.
    let mut cut: Option<Instant> = None;
    loop {
        let quiet = cut.map(|end| (Instant::now() + QUIET).min(end));
        let events = tokio::select! {
            read = keys.read(&mut a), if keys_open => match read {
                Ok(n) if n > 0 => state.lock().tty.input(&a[..n]),
                _ => {
                    // The client's EOF: the child's input ends, as at a
                    // hang-up of its line.
                    keys_open = false;
                    state.lines = None;
                    Vec::new()
                }
            },
            read = from_child.read(&mut b), if !state.stopped => match read {
                Ok(n) if n > 0 => {
                    let out = state.lock().tty.output(&b[..n]);
                    if !state.show(&out, &mut screen).await {
                        break;
                    }
                    Vec::new()
                }
                _ => break,
            },
            got = told.recv(), if told_open => match got {
                Some(Told::Events(events)) => events,
                Some(Told::DropOutput) => {
                    state.held.clear();
                    Vec::new()
                }
                Some(Told::Output(on)) => {
                    if on {
                        if !state.start(&mut screen).await {
                            break;
                        }
                    } else {
                        state.stopped = true;
                    }
                    Vec::new()
                }
                None => {
                    told_open = false;
                    Vec::new()
                }
            },
            changed = size.changed(), if size_open => match changed {
                Ok(()) => {
                    let now = *size.borrow_and_update();
                    state.lock().tty.resize(now)
                }
                Err(_) => {
                    size_open = false;
                    Vec::new()
                }
            },
            () = turned(&mut exited), if cut.is_none() => {
                cut = Some(Instant::now() + AFTER_EXIT);
                Vec::new()
            },
            () = tokio::time::sleep_until(quiet.unwrap_or_else(Instant::now)), if quiet.is_some() => break,
        };
        if !state.act(events, &mut screen).await {
            break;
        }
    }
    let _ = screen.flush().await;
    stop.store(true, Ordering::SeqCst);
}

/// The child's input, fed by its own task, so that a child that reads
/// nothing holds no key and no output of the screen.
fn feed<W: AsyncWrite + Unpin + Send + 'static>(mut to_child: W) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(LINES);
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if to_child.write_all(&line).await.is_err() {
                return;
            }
        }
        // The sender gone is the end of input: half-close of the socket.
        let _ = to_child.shutdown().await;
    });
    tx
}
