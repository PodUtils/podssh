//! The program of a session channel of `podssh serve` (T-108): a command as
//! `SHELL -c COMMAND`, or the shell as a login shell, on three pipes, in a
//! session of its own, run as the user that runs serve; its output to the
//! channel, then its end: `exit-status` or `exit-signal`, EOF, close.
//!
//! Starting the user's shell is what the client asked for (rule 3 of
//! `AGENTS.md`): no preload, no shim, no helper.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::server::{Handle, Msg};
use russh::{ChannelId, ChannelWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::time::Instant;

use super::channel::{Open, Program};

/// After the child ends, how long its pipes may stay silent before they
/// are left: a job that it put in the background can hold them open.
pub const QUIET: Duration = Duration::from_secs(2);

/// After the child ends, the longest its pipes are read at all. What a
/// child left in a pipe is at most the pipe's buffer, so this bounds a
/// background job that writes on, not the output of the child.
pub const AFTER_EXIT: Duration = Duration::from_secs(30);

/// The size of each read of the child's output.
const CHUNK: usize = 32 * 1024;

/// The arguments of `shell` for `program`: argv\[0\] is the shell's name, with
/// a dash for a login shell, as sshd and login(1) give it.
fn argv(shell: &Path, program: &Program<'_>) -> Result<(OsString, Vec<OsString>), String> {
    let name = shell.file_name().map_or_else(|| shell.as_os_str().to_os_string(), |n| n.to_os_string());
    match program {
        Program::Command(command) => {
            if command.contains(&0) {
                return Err("the command holds a NUL byte, which no program takes".into());
            }
            Ok((name, vec!["-c".into(), std::ffi::OsStr::from_bytes(command).to_os_string()]))
        }
        Program::Login => {
            let mut login = OsString::from("-");
            login.push(name);
            Ok((login, Vec::new()))
        }
    }
}

/// Start `program` with `shell` in `env` for the channel `open`, and the
/// task that serves it to its end. `Err` is the line for the client's
/// stderr; the request then fails, and the channel can ask again.
pub(super) fn spawn(
    open: &mut Open,
    id: ChannelId,
    shell: &Path,
    program: Program<'_>,
    env: Vec<(OsString, OsString)>,
) -> Result<(), String> {
    let (arg0, args) = argv(shell, &program)?;
    let mut cmd = Command::new(shell);
    cmd.arg0(arg0).args(args).env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.current_dir(super::env::workdir(&env));
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // The child leads a session and a process group of its own: a signal
    // request reaches each process that it starts, and none of them shares
    // serve's.
    // SAFETY: setsid is async-signal-safe and touches no memory of the
    // parent; it fails only for a group's leader, which a new child is not.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("{}: {}", shell.display(), super::shell::not_started(&e)))?;
    let Some(write) = open.write.take() else {
        // A channel runs one program; the handler asks before it starts one.
        let _ = child.start_kill();
        return Err("a program runs on this channel already".into());
    };
    if let Some(pid) = child.id() {
        open.group.store(pid as i32, Ordering::SeqCst);
    }
    if let Some(stdin) = child.stdin.take() {
        open.give_stdin(stdin);
    }
    let running = Running { write, handle: open.handle.clone(), id, group: open.group.clone() };
    tokio::spawn(running.run(child, open.closed.clone()));
    Ok(())
}

/// The program's side of the channel, once it runs.
struct Running {
    write: ChannelWriteHalf<Msg>,
    handle: Handle,
    id: ChannelId,
    group: Arc<AtomicI32>,
}

impl Running {
    /// Pump stdout as data and stderr as extended data 1 while the child
    /// runs; after it ends, read the pipes to their end within [`QUIET`] and
    /// [`AFTER_EXIT`]; then its status, EOF and close, in that order. A
    /// client that closes the channel first ends the pumps: the child then
    /// meets closed pipes, as under sshd.
    async fn run(self, mut child: Child, mut closed: watch::Receiver<bool>) {
        let (exited_tx, exited) = watch::channel(false);
        let out = child.stdout.take().map(|p| tokio::spawn(pump(p, self.write.make_writer(), exited.clone())));
        let err = child.stderr.take().map(|p| tokio::spawn(pump(p, self.write.make_writer_ext(Some(1)), exited)));
        let mut pumps: Vec<_> = [out, err].into_iter().flatten().collect();
        let aborts: Vec<_> = pumps.iter().map(|p| p.abort_handle()).collect();
        let abort = || aborts.iter().for_each(|a| a.abort());
        let status = tokio::select! {
            status = child.wait() => status,
            () = turned(&mut closed) => {
                abort();
                // tokio reaps the child when it ends; nothing waits here.
                return;
            }
        };
        self.group.store(0, Ordering::SeqCst);
        let _ = exited_tx.send(true);
        tokio::select! {
            () = drained_all(&mut pumps) => {}
            () = turned(&mut closed) => {
                abort();
                return;
            }
        }
        self.end(status).await;
    }

    /// The end of the channel: one of `exit-status` and `exit-signal`
    /// always comes before the close, so that a client never has to guess
    /// (T-026 reads it); then EOF and close.
    async fn end(self, status: std::io::Result<ExitStatus>) {
        match status.as_ref().ok().and_then(ExitStatus::signal) {
            Some(number) => {
                let core = status.as_ref().is_ok_and(ExitStatus::core_dumped);
                let signal = crate::signals::from_number(number);
                let _ = self.handle.exit_signal_request(self.id, signal, core, String::new(), String::new()).await;
            }
            None => {
                // A wait that failed has no status; 255 is OpenSSH's own.
                let code = status.ok().and_then(|s| s.code()).unwrap_or(255);
                let _ = self.write.exit_status(code as u32).await;
            }
        }
        let _ = self.write.eof().await;
        let _ = self.write.close().await;
    }
}

/// Wait until `flag` is true. A sender gone is an end too. The value is
/// copied out at once, as a borrow of a watch held across a wait would make
/// the task's future unsendable.
async fn turned(flag: &mut watch::Receiver<bool>) {
    loop {
        let on = *flag.borrow_and_update();
        if on || flag.changed().await.is_err() {
            return;
        }
    }
}

/// Wait for each pump in turn.
async fn drained_all(pumps: &mut [tokio::task::JoinHandle<()>]) {
    for pump in pumps.iter_mut() {
        let _ = pump.await;
    }
}

/// Copy `pipe` to `to` until its end; after `exited` turns true, until a
/// silence of [`QUIET`] or [`AFTER_EXIT`] in all. A write that fails (the
/// channel is gone) ends it, and the dropped pipe tells the child.
async fn pump(mut pipe: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin, mut exited: watch::Receiver<bool>) {
    let mut buf = vec![0u8; CHUNK];
    let mut cut: Option<Instant> = None;
    loop {
        let read = match cut {
            Some(end) => {
                let until = (Instant::now() + QUIET).min(end);
                match tokio::time::timeout_at(until, pipe.read(&mut buf)).await {
                    Ok(read) => read,
                    Err(_) => return,
                }
            }
            None => tokio::select! {
                read = pipe.read(&mut buf) => read,
                () = turned(&mut exited) => {
                    cut = Some(Instant::now() + AFTER_EXIT);
                    continue;
                }
            },
        };
        match read {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_login_shell_has_a_dash_and_a_command_runs_with_dash_c() {
        let (arg0, args) = argv(Path::new("/bin/sh"), &Program::Login).unwrap();
        assert_eq!((arg0.as_os_str(), args.len()), (std::ffi::OsStr::new("-sh"), 0));
        let (arg0, args) = argv(Path::new("/bin/bash"), &Program::Command(b"echo hi")).unwrap();
        assert_eq!(arg0, OsString::from("bash"));
        assert_eq!(args, vec![OsString::from("-c"), OsString::from("echo hi")]);
        assert!(argv(Path::new("/bin/sh"), &Program::Command(b"a\0b")).is_err());
    }
}
