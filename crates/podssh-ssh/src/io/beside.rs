//! A wait on russh's session beside the channel's messages (T-780).
//!
//! russh's loop puts each CHANNEL_DATA into the channel's bounded queue and
//! waits there, inline, while the queue is full; it takes a write of the
//! pump (an EOF, a key, a window's change, a signal) from a bounded queue of
//! its own, and only while no data waits for the far end's window. So a pump
//! that awaits a write and takes no message meanwhile can wait on a loop
//! that waits on it: the loop for room in the channel's queue, the pump for
//! room in the loop's. Each wait of a pump on the session drains the channel
//! into a backlog instead, and the pump hands the backlog on, in order,
//! before the channel's next message.
//!
//! Each wait on a session's write with a channel open goes through here: the
//! pumps of `io.rs` and `mux/`, `exec`, the gateway of `serve` and `podssh
//! ping`'s measures (T-923).

use std::collections::VecDeque;
use std::future::Future;

use russh::{ChannelMsg, ChannelReadHalf};

/// The most bytes that a backlog keeps. Past it a wait drains no more, and
/// russh's loop waits on the queue as it did before: russh grants the far
/// end's window as data comes, not as it is taken, so the backlog needs a
/// bound of its own.
pub const BACKLOG_MOST: usize = 16 << 20;

/// What a message costs in a backlog at the least: a bound on the count of
/// messages with no data, too.
const MSG_COST: usize = 64;

/// Where a pump takes its messages: russh's channel, or a stand-in.
pub trait Source {
    type Msg: Send;
    /// The next message; `None` once the channel has ended.
    fn wait(&mut self) -> impl Future<Output = Option<Self::Msg>> + Send + '_;
    /// The bytes that `msg` keeps.
    fn size(msg: &Self::Msg) -> usize;
}

impl Source for ChannelReadHalf {
    type Msg = ChannelMsg;

    fn wait(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send + '_ {
        ChannelReadHalf::wait(self)
    }

    fn size(msg: &ChannelMsg) -> usize {
        match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => data.len(),
            _ => 0,
        }
    }
}

/// The messages taken beside a wait, not yet handed on.
pub struct Backlog<M> {
    msgs: VecDeque<(M, usize)>,
    bytes: usize,
    /// The channel ended behind the messages kept.
    ended: bool,
    most: usize,
}

impl<M> Default for Backlog<M> {
    fn default() -> Self {
        Backlog::with_most(BACKLOG_MOST)
    }
}

impl<M> Backlog<M> {
    /// A backlog that keeps `most` bytes at the most.
    pub fn with_most(most: usize) -> Self {
        Backlog { msgs: VecDeque::new(), bytes: 0, ended: false, most }
    }

    fn push(&mut self, msg: M, size: usize) {
        let cost = size.max(MSG_COST);
        self.bytes = self.bytes.saturating_add(cost);
        self.msgs.push_back((msg, cost));
    }

    fn pop(&mut self) -> Option<M> {
        let (msg, cost) = self.msgs.pop_front()?;
        self.bytes = self.bytes.saturating_sub(cost);
        Some(msg)
    }

    /// How many messages wait to be handed on.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.msgs.len()
    }

    /// Whether a wait may take one more message.
    fn room(&self) -> bool {
        !self.ended && self.bytes < self.most
    }
}

/// The channel's next message: the backlog's first, else the source's own.
/// Each read of a pump goes through here, so that the order holds.
pub async fn next<S: Source>(source: &mut S, backlog: &mut Backlog<S::Msg>) -> Option<S::Msg> {
    if let Some(msg) = backlog.pop() {
        return Some(msg);
    }
    if backlog.ended {
        return None;
    }
    source.wait().await
}

/// `op`, a wait on russh's session, while the source's messages go into
/// `backlog`; `polled` is called at each poll of the source's wait (the
/// pump's watch, `busy.rs`).
pub async fn beside<F: Future, S: Source>(
    op: F,
    source: &mut S,
    backlog: &mut Backlog<S::Msg>,
    polled: &(dyn Fn() + Sync),
) -> F::Output {
    tokio::pin!(op);
    loop {
        let room = backlog.room();
        tokio::select! {
            biased;
            out = &mut op => return out,
            msg = noted(source.wait(), polled), if room => match msg {
                Some(msg) => {
                    let size = S::size(&msg);
                    backlog.push(msg, size);
                }
                None => backlog.ended = true,
            },
        }
    }
}

/// `fut`, with `polled` called at each of its polls.
fn noted<'a, F: Future + 'a>(fut: F, polled: &'a (dyn Fn() + Sync)) -> impl Future<Output = F::Output> + 'a {
    let mut fut = Box::pin(fut);
    std::future::poll_fn(move |cx| {
        polled();
        fut.as_mut().poll(cx)
    })
}

#[cfg(test)]
#[path = "beside_model.rs"]
pub(crate) mod model;

#[cfg(test)]
#[path = "beside_tests.rs"]
mod tests;
