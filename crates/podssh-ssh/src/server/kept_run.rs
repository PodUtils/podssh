//! The child of a shell that may be kept (T-159), on a pty: its start as
//! the first channel's program, and its end, apart from `kept.rs` so that
//! each file stays short.
//!
//! The child's end goes to the channel that has the shell then, which may
//! be another than the one that started it. A shell that must end (a lease
//! that ran out, or a client that left a shell never kept) is hung up as a
//! terminal that goes away; after a lease, a group that is still there
//! after [`KILL_AFTER`] is killed.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::process::Child;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::channel::Open;
use super::child::{pump_told, turned, Running};
use super::kept::{reports_for, watch_close, Attached, Keeper, Out, Shell, KILL_AFTER};
use super::predict::Teller;
use super::pty;
use super::pty_child::Master;
use super::stop::{to_group, HANGUP};
use crate::terminal::Size;

/// Serve `child`, the login shell of `open` on `master`, as a shell that
/// may be kept: its output through [`Out`], the channel of `open` first,
/// and its end by [`finish`]. A `keep@podssh` that the shelf refuses runs
/// the shell unkept, and the channel's stderr says why. `motd` comes before
/// the child's first byte (T-119), and `marks` lives as long as the shell
/// (T-120), which can outlive the channel that started it.
pub(super) fn start(
    open: &mut Open,
    keeper: &Keeper,
    id: String,
    running: Running,
    pair: (Arc<AsyncFd<OwnedFd>>, Child),
    motd: std::io::Cursor<Vec<u8>>,
    marks: Option<super::marks::Files>,
) {
    let (master, child) = pair;
    let (write, handle, channel, group, tally) = running.into_parts();
    let fd = master.clone();
    let resize = move |size: Size| {
        let _ = pty::set_size(fd.get_ref().as_raw_fd(), size);
    };
    let shell = Shell::new(keeper, id, Box::new(Master(master.clone())), Box::new(resize), group);
    shell.reports_from(master.clone());
    // Local echo's reports, where the first channel asked (T-896).
    let (told, count) = reports_for(&shell, open.predict, &write);
    let held = shell.first(Attached::new(write, handle, channel, tally).with_reports(told));
    if let Some(name) = keeper.keep.as_deref()
        && let Err(why) = keeper.shelf.put(&shell, name)
    {
        open.told = Some(format!("podssh serve: this shell is not kept: {why}\r\n"));
    }
    open.give_stdin(shell.writer(held.generation, count));
    watch_close(&held, open.closed.clone());
    open.kept = Some(held);
    let (exited_tx, exited) = watch::channel(false);
    // The pump tells the reports of the channel that has the shell then.
    let (from, teller) = (tokio::io::AsyncReadExt::chain(motd, Master(master)), Some(Teller::Kept(shell.clone())));
    let output = tokio::spawn(pump_told(from, Out(shell.clone()), exited, teller));
    tokio::spawn(async move {
        finish(shell, child, output, exited_tx).await;
        // The files of the marks go when the shell does.
        drop(marks);
    });
}

/// Wait for the child or for the shell's end. At the child's end, the pty
/// is read to its end, then the status goes to the channel that has the
/// shell, if one has it.
async fn finish(shell: Arc<Shell>, mut child: Child, output: JoinHandle<()>, exited: watch::Sender<bool>) {
    let mut gone = shell.gone();
    let status = tokio::select! {
        status = child.wait() => status,
        () = turned(&mut gone) => {
            output.abort();
            hang_up(&shell, &mut child).await;
            shell.group.store(0, Ordering::SeqCst);
            if let Some(attached) = shell.ended_with(None) {
                attached.told("podssh serve: the kept shell ended\r\n".to_string());
            }
            return;
        }
    };
    shell.group.store(0, Ordering::SeqCst);
    let _ = exited.send(true);
    let abort = output.abort_handle();
    tokio::select! {
        _ = output => {}
        () = turned(&mut gone) => abort.abort(),
    }
    let code = status.as_ref().ok().and_then(|s| s.code()).and_then(|c| u32::try_from(c).ok());
    if let Some(attached) = shell.ended_with(code) {
        let (write, handle, id, tally) = attached.into_parts();
        Running::of(write, handle, id, shell.group.clone(), tally).end(status).await;
    }
}

/// SIGHUP and SIGCONT to the shell's group, as the kernel sends both when
/// a terminal goes away. After a lease (a kept shell), a group that runs
/// on past [`KILL_AFTER`] is killed; a shell never kept is waited for, as
/// without T-159 (`child::Running::finish`).
async fn hang_up(shell: &Shell, child: &mut Child) {
    let group = shell.group.load(Ordering::SeqCst);
    HANGUP.iter().for_each(|signal| to_group(group, *signal));
    if shell.name().is_none() {
        let _ = child.wait().await;
        return;
    }
    if tokio::time::timeout(KILL_AFTER, child.wait()).await.is_err() {
        to_group(group, libc::SIGKILL);
        let _ = child.wait().await;
    }
}
