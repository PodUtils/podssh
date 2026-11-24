//! Local echo's reports from a shell shared by name (T-837, T-896): each
//! seat that asked (`env predict@podssh v1`, the owner's or a writing
//! name's) gets the count of its own bytes that the lease let through to
//! the tty, from 0, as its client counts them.
//!
//! The seats read the output through the hub's broadcast, each at its own
//! pace, so a report cannot go out of a task of its own: it could pass the
//! echo that it counts, still in the broadcast or in the pump. Each item of
//! the broadcast is output and then each asking seat's report at the moment
//! after it ([`Said`]), made by the one task that reads the tty, after the
//! output that it read; a count that falls due with no output (a line with
//! no echo) is an item with no bytes, made by the same task ([`Ticks`]).
//! Each seat's view writes its own report after the bytes before it, and
//! once per change; a seat that lags skips to an item that holds the counts
//! of now. The owner's reports ride the same broadcast, read by a task of
//! the owner's, as its output reached its channel before the item did.
//!
//! On a kernel pty a byte counts once the master took it. On serve's own
//! tty (`--pty line`, `notify`) it counts once the discipline read it
//! ([`Taken`]), whose echo the same loop writes before its next tick; the
//! flags come from the discipline, not from a master.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that share one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, watch, Notify};
use tokio::time::Instant;

use super::predict_count::Applied;
use super::share::Hub;
use crate::predict::report::{encode, Flags, Report, EXT};

/// The flags where none can be read: a line with no echo, so no guess
/// shows.
pub(super) const UNREAD: Flags = Flags { echo: false, canonical: true };

/// Where a shared shell's flags come from, read at each report.
pub(super) type FlagsOf = Box<dyn Fn() -> Flags + Send + Sync>;

/// The flags of serve's line discipline (T-111): it always echoes and
/// edits a line; the program on its pipes cannot turn either off.
pub(super) fn cooked() -> FlagsOf {
    Box::new(|| Flags { echo: true, canonical: true })
}

/// One item of a shared shell's broadcast: output, then the report of
/// each seat that asked, at the moment after it. No bytes: a tick.
#[derive(Clone, Debug)]
pub(super) struct Said {
    pub(super) bytes: Bytes,
    pub(super) told: Option<Arc<[(u64, Report)]>>,
}

/// One asking seat's count, and the report that the broadcast last held.
#[derive(Default)]
struct Count {
    applied: Applied,
    offset: u64,
    sent: Option<Report>,
}

/// The reports of a shared shell's seats.
#[derive(Default)]
pub(super) struct Tells {
    seats: Mutex<HashMap<u64, Count>>,
    /// Wakes the task that ticks at a write of an asking seat.
    wake: Notify,
    flags: OnceLock<FlagsOf>,
    /// Serve's own tty: each write, as the seat and its length, in the
    /// order of the discipline's input, counted when the discipline reads
    /// it. Unset on a kernel pty, which takes each byte at its write.
    order: OnceLock<Mutex<VecDeque<(u64, usize)>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Tells {
    /// The shell's flags come from `flags`; on serve's own tty (`at_read`)
    /// a byte counts once the discipline read it. Set once, at the open.
    pub(super) fn source(&self, flags: FlagsOf, at_read: bool) {
        let _ = self.flags.set(flags);
        if at_read {
            let _ = self.order.set(Mutex::new(VecDeque::new()));
        }
    }

    /// `seat` asked: its count starts at 0.
    pub(super) fn ask(&self, seat: u64) {
        lock(&self.seats).insert(seat, Count::default());
    }

    /// `seat` left: no more reports of it.
    pub(super) fn leave(&self, seat: u64) {
        lock(&self.seats).remove(&seat);
    }

    /// Before the lease writes `n` bytes of `seat` to serve's own tty: their
    /// place in the discipline's input. Each seat's, so that the places of
    /// the others hold.
    pub(super) fn before(&self, seat: u64, n: usize) {
        if let Some(order) = self.order.get() {
            lock(order).push_back((seat, n));
        }
    }

    /// The lease wrote `n` bytes of `seat`: on a kernel pty they count now.
    pub(super) fn wrote(&self, seat: u64, n: usize) {
        if self.order.get().is_none() {
            self.count(seat, n, Instant::now());
        }
    }

    /// The discipline read `n` bytes of its input: each seat's part of them
    /// counts now.
    pub(super) fn taken(&self, n: usize) {
        let Some(order) = self.order.get() else { return };
        let now = Instant::now();
        let mut parts = Vec::new();
        {
            let mut order = lock(order);
            let mut left = n;
            while left > 0 {
                let Some(front) = order.front_mut() else { break };
                let part = front.1.min(left);
                parts.push((front.0, part));
                front.1 -= part;
                left -= part;
                if front.1 == 0 {
                    order.pop_front();
                }
            }
        }
        for (seat, part) in parts {
            self.count(seat, part, now);
        }
    }

    /// Count `n` bytes of `seat` at `now`, where it asked.
    fn count(&self, seat: u64, n: usize, now: Instant) {
        let seats = lock(&self.seats);
        let Some(count) = seats.get(&seat) else { return };
        count.applied.wrote(n, now);
        drop(seats);
        // A permit is kept where no task waits, so no write is missed.
        self.wake.notify_one();
    }

    /// The report of each asking seat now; None where no seat asked, or,
    /// unless `always`, where no report changed since the last.
    pub(super) fn reports(&self, always: bool) -> Option<Arc<[(u64, Report)]>> {
        if lock(&self.seats).is_empty() {
            return None;
        }
        // Read outside the seats' lock: a discipline's flags take its own.
        let flags = self.flags.get().map_or(UNREAD, |of| of());
        let now = Instant::now();
        let mut changed = false;
        let mut seats = lock(&self.seats);
        let told: Vec<(u64, Report)> = seats
            .iter_mut()
            .map(|(seat, count)| {
                if let Some(end) = count.applied.ripe(now) {
                    count.offset = end;
                }
                let report = Report { offset: count.offset, flags };
                changed |= count.sent != Some(report);
                count.sent = Some(report);
                (*seat, report)
            })
            .collect();
        (always || changed).then(|| told.into())
    }

    /// Until the next count of an asking seat falls due; with none, until
    /// a write of one brings one.
    pub(super) async fn fall_due(&self) {
        loop {
            // Made before the look, so that a write between them wakes it.
            let woken = self.wake.notified();
            let due = lock(&self.seats).values().filter_map(|count| count.applied.due()).min();
            match due {
                Some(at) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(at) => return,
                        () = woken => {}
                    }
                }
                None => woken.await,
            }
        }
    }
}

/// The ticks of a shared shell, for the one task that reads its tty: a
/// report that falls due with no output goes into the broadcast in its
/// place, after each output that the task read.
pub struct Ticks(pub(super) Arc<Hub>);

impl Ticks {
    /// Ends when a count of an asking seat falls due; it owns what it reads.
    pub(super) fn falls_due(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let hub = self.0.clone();
        Box::pin(async move { hub.tells.fall_due().await })
    }

    /// The reports that changed, as an item with no bytes.
    pub(super) fn tick(&self) {
        self.0.tick();
    }
}

/// The discipline's input on serve's own tty: each byte counts for its seat
/// once the discipline read it.
pub(super) struct Taken<R> {
    pub(super) inner: R,
    pub(super) hub: Arc<Hub>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Taken<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        if matches!(polled, Poll::Ready(Ok(()))) && n > 0 {
            self.hub.tells.taken(n);
        }
        polled
    }
}

/// The reports of one seat's channel, written after the output before them.
pub(super) struct SeatTold {
    seat: u64,
    out: Pin<Box<dyn AsyncWrite + Send>>,
    told: Option<Report>,
}

impl SeatTold {
    /// The reports of `seat` on the channel of `write`.
    pub(super) fn new(write: &ChannelWriteHalf<Msg>, seat: u64) -> SeatTold {
        SeatTold { seat, out: Box::pin(write.make_writer_ext(Some(EXT))), told: None }
    }

    /// This seat's report in `said`, where it changed. `Err`: the channel
    /// is gone.
    pub(super) async fn tell(&mut self, said: &Said) -> io::Result<()> {
        let mine = said.told.as_deref().and_then(|told| told.iter().find(|(seat, _)| *seat == self.seat));
        let Some(&(_, report)) = mine else { return Ok(()) };
        if self.told == Some(report) {
            return Ok(());
        }
        self.out.write_all(&encode(report)).await?;
        self.told = Some(report);
        Ok(())
    }
}

/// The owner's reports: its output went to its channel before each item
/// of the broadcast was made, so each report here follows it. Ends with
/// the shell's output, or the owner's channel.
pub(super) async fn owner_tells(
    mut from: broadcast::Receiver<Said>,
    mut told: SeatTold,
    mut closed: watch::Receiver<bool>,
) {
    loop {
        let next = tokio::select! {
            next = from.recv() => next,
            () = super::share_view::gone(&mut closed) => return,
        };
        match next {
            Ok(said) => {
                if told.tell(&said).await.is_err() {
                    return;
                }
            }
            // The next item holds the counts of now.
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
#[path = "share_told_tests.rs"]
mod tests;
