//! A pty request where no pty opens (T-111, route 3 of T-248): the program
//! runs on pipes, and serve itself is its line discipline, pod-term's cooked
//! mode (PodUtils/podcrates): the client's keys are echoed and edited here,
//! a line goes to the program's stdin when it is submitted, Ctrl-C and
//! Ctrl-\ go to the program's process group as SIGINT and SIGQUIT, and the
//! program's output is written around the line under edit, each `\n` as
//! `\r\n`, as on a pty.
//!
//! The discipline assumes a shell that prints no prompt and survives a
//! Ctrl-C (the server of podvm): a login shell runs non-interactive on its
//! pipes, and its first line is a trap of SIGINT and SIGQUIT, so that the
//! signal ends the command in the foreground and not the shell (a caught
//! signal is the default again in the shell's children). The discipline
//! draws the prompt.

use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use pod_term::echo::{Event, Sig, IDLE, PROMPT};
use pod_term::session::{Facts, Session};
use pod_term::window::Size;
use russh::{ChannelId, Pty};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch};

use super::channel::{Open, Program};
use super::child::{command, own_session, pump, Running};

/// The first line of a login shell: Ctrl-C and Ctrl-\ end the command in
/// the foreground, and the shell goes on.
pub const TRAP: &[u8] = b"trap : INT QUIT\n";

/// The programs that need a tty to draw on: a line that starts with one
/// gets a note first, then runs (Approach item 5 of T-111).
const FULL_SCREEN: &[&str] = &["vi", "vim", "nvim", "nano", "less", "more", "top", "htop", "man", "emacs", "watch"];

/// The bytes that may wait between the client's reader and the
/// discipline, and between each output of the child and the discipline.
const PIPE: usize = 64 * 1024;

/// The lines that may wait for the child's stdin.
const LINES: usize = 128;

/// A pty request granted with serve as the line discipline, from the
/// request until the program starts; then its sizes, for window changes.
pub(super) struct LineGrant {
    pub(super) term: String,
    pub(super) utf8: bool,
    pub(super) size: watch::Sender<Size>,
    /// Whether serve answers the child's tty calls (T-776), in place of
    /// the line discipline on pipes.
    pub(super) notify: bool,
}

impl LineGrant {
    pub(super) fn new(term: &str, cols: u32, rows: u32, modes: &[(Pty, u32)]) -> LineGrant {
        let utf8 = modes.iter().any(|(mode, on)| *mode == Pty::IUTF8 && *on != 0);
        let (size, _) = watch::channel(size_of(cols, rows));
        LineGrant { term: super::pty::term_of(term), utf8, size, notify: false }
    }

    /// A window change: the discipline draws the line at the new width.
    pub(super) fn resize(&self, cols: u32, rows: u32) {
        self.size.send_replace(size_of(cols, rows));
    }
}

/// The size of a request in pod-term's terms; zero is sshd's 80x24.
fn size_of(cols: u32, rows: u32) -> Size {
    let cut = |v: u32, default: u16| if v == 0 { default } else { u16::try_from(v).unwrap_or(u16::MAX) };
    Size { rows: cut(rows, 24), cols: cut(cols, 80) }
}

/// Start `program` on pipes with serve as its line discipline, and the
/// tasks that serve it to its end. `Err` is the line for the client's stderr.
pub(super) fn spawn(
    open: &mut Open,
    id: ChannelId,
    shell: &Path,
    program: Program<'_>,
    env: Vec<(OsString, OsString)>,
) -> Result<(), String> {
    let Some(grant) = open.line.as_ref() else { return Err("no pty on this channel".into()) };
    let (utf8, size) = (grant.utf8, grant.size.subscribe());
    let login = matches!(program, Program::Login);
    // TERM is the request's; the pipes have no path for SSH_TTY.
    let env = super::env::with_tty(env, &grant.term, None);
    let mut cmd = command(shell, &program, env)?;
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    own_session(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| format!("{}: {}", shell.display(), super::shell::not_started(&e)))?;
    let running = Running::take(open, id, &mut child)?;
    let (keys_in, keys) = tokio::io::duplex(PIPE);
    open.give_stdin(Box::new(keys_in));
    let (exited_tx, exited) = watch::channel(false);
    let (out_in, out) = tokio::io::duplex(PIPE);
    let (err_in, err) = tokio::io::duplex(PIPE);
    let mut tasks = Vec::new();
    if let Some(p) = child.stdout.take() {
        tasks.push(tokio::spawn(pump(p, out_in, exited.clone())));
    }
    if let Some(p) = child.stderr.take() {
        tasks.push(tokio::spawn(pump(p, err_in, exited)));
    }
    let lines = child.stdin.take().map(feed_lines);
    let session = Session::with_utf8(Facts { selected: true, ..Facts::default() }, utf8).sized(*size.borrow());
    let line = Line { session, lines, group: open.group.clone(), login };
    tasks.push(tokio::spawn(line.run(keys, [out, err], size, running.write.make_writer())));
    tokio::spawn(running.finish(child, tasks, exited_tx, open.closed.clone()));
    Ok(())
}

/// The child's stdin, fed by its own task, so that a child that reads
/// nothing holds no key and no output of the screen.
fn feed_lines(mut stdin: tokio::process::ChildStdin) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(LINES);
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if stdin.write_all(&line).await.is_err() {
                return;
            }
        }
        // The sender gone is the end of input: the dropped pipe says so.
    });
    tx
}

/// The discipline between the client and the child.
struct Line {
    session: Session,
    /// The child's stdin; None once input ended.
    lines: Option<mpsc::Sender<Vec<u8>>>,
    group: Arc<AtomicI32>,
    login: bool,
}

impl Line {
    /// Until both of the child's outputs end: the client's keys, the
    /// child's output, the window's size, and the pause that ends a key
    /// left open, each through the discipline to the screen.
    async fn run(
        mut self,
        mut keys: DuplexStream,
        [mut out, mut err]: [DuplexStream; 2],
        mut size: watch::Receiver<Size>,
        mut screen: impl AsyncWrite + Unpin,
    ) {
        if self.login {
            self.give_child(TRAP.to_vec()).await;
            if screen.write_all(PROMPT).await.is_err() {
                return;
            }
        }
        let (mut keys_open, mut out_open, mut err_open, mut size_open) = (true, true, true, true);
        let (mut a, mut b, mut c) = (vec![0u8; 4096], vec![0u8; 32 * 1024], vec![0u8; 32 * 1024]);
        while out_open || err_open {
            let waiting = self.session.waiting();
            let events = tokio::select! {
                read = keys.read(&mut a), if keys_open => match read {
                    Ok(n) if n > 0 => self.session.on_local_bytes(&a[..n]),
                    _ => {
                        keys_open = false;
                        self.session.on_eof()
                    }
                },
                read = out.read(&mut b), if out_open => output(&mut self.session, read, &b, &mut out_open),
                read = err.read(&mut c), if err_open => output(&mut self.session, read, &c, &mut err_open),
                changed = size.changed(), if size_open => match changed {
                    Ok(()) => {
                        let now = *size.borrow_and_update();
                        self.session.on_resize(now)
                    }
                    Err(_) => {
                        size_open = false;
                        Vec::new()
                    }
                },
                () = tokio::time::sleep(IDLE), if waiting => self.session.on_idle(),
            };
            if !self.act(events, &mut screen).await {
                return;
            }
        }
        let _ = screen.flush().await;
    }

    /// Carry out the discipline's events; false once the screen is gone.
    async fn act(&mut self, events: Vec<Event>, screen: &mut (impl AsyncWrite + Unpin)) -> bool {
        for event in events {
            match event {
                Event::ToLocal(bytes) => {
                    if screen.write_all(&bytes).await.is_err() {
                        return false;
                    }
                }
                Event::ToRemote(line) => {
                    if let Some(note) = full_screen(&line) {
                        let mut said = Vec::new();
                        for e in self.session.on_remote_bytes(note.as_bytes()) {
                            if let Event::ToLocal(bytes) = e {
                                said.extend_from_slice(&bytes);
                            }
                        }
                        if screen.write_all(&said).await.is_err() {
                            return false;
                        }
                    }
                    self.give_child(line).await;
                }
                Event::Signal(sig) => self.signal(sig),
                Event::Eof => self.lines = None,
                // Only the transparent mode makes a size; nothing below has one.
                Event::Size(_) => {}
            }
        }
        true
    }

    async fn give_child(&mut self, line: Vec<u8>) {
        if let Some(lines) = &self.lines {
            if lines.send(line).await.is_err() {
                self.lines = None;
            }
        }
    }

    /// Ctrl-C or Ctrl-\: to the child's whole process group, as a pty's
    /// discipline sends it to the foreground group.
    fn signal(&self, sig: Sig) {
        let number = match sig {
            Sig::Int => libc::SIGINT,
            Sig::Quit => libc::SIGQUIT,
        };
        let group = self.group.load(Ordering::SeqCst);
        if group > 0 {
            // SAFETY: kill has no memory effect; a group that ended gives ESRCH.
            unsafe {
                libc::kill(-group, number);
            }
        }
    }
}

/// The child's output of one read through the discipline; an end or an
/// error of that output closes it.
fn output(session: &mut Session, read: std::io::Result<usize>, buf: &[u8], open: &mut bool) -> Vec<Event> {
    match read {
        Ok(n) if n > 0 => session.on_remote_bytes(&buf[..n]),
        _ => {
            *open = false;
            Vec::new()
        }
    }
}

/// The note for a line that starts a program that draws on a tty, which a
/// pipe is not: said, then the line runs as typed.
fn full_screen(line: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(line);
    let word = text.split_whitespace().next()?;
    let name = word.rsplit('/').next().unwrap_or(word);
    FULL_SCREEN
        .contains(&name)
        .then(|| format!("podssh serve: {name} needs a pty, and this host has none (no /dev/ptmx): it may not draw\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_screen_program_gets_a_note_and_others_none() {
        assert!(full_screen(b"vi notes.txt\n").is_some_and(|n| n.contains("vi needs a pty")));
        assert!(full_screen(b"  /usr/bin/less /etc/os-release\n").is_some_and(|n| n.contains("less needs a pty")));
        assert_eq!(full_screen(b"echo vi\n"), None);
        assert_eq!(full_screen(b"\n"), None);
    }

    #[test]
    fn a_zero_size_is_80_by_24() {
        assert_eq!(size_of(0, 0), Size { rows: 24, cols: 80 });
        assert_eq!(size_of(132, 43), Size { rows: 43, cols: 132 });
    }
}
