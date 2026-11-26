//! The bytes of a gateway (T-836): each channel of the client carried to a
//! channel of the upstream, one task for each way. russh joins no two
//! connections at the packet layer, so each message is read on one side
//! and said again on the other: data, stderr, EOF, the exit status and the
//! exit signal, and the close. The client's channel opens its window as the
//! upstream takes its bytes (T-118's rule): a slow upstream holds its own
//! channel alone. The upstream's replies to the requests that the handler
//! forwards come back in their order, as RFC 4254 sends them, through a
//! queue that the handler reads.
//!
//! Each write goes beside its side's reads (T-923): russh's loop of each
//! connection puts a message into its channel's bounded queue inline, and
//! takes a write only after. A task that awaited a write and read nothing
//! closes a cycle of four waits: the client's side on the upstream's loop,
//! that loop on the queue of the upstream's side, that side on the client's
//! loop, and that loop on the queue of the client's side.

use std::sync::Arc;
use std::time::Duration;

use russh::server::{Handle, Msg as Down};
use russh::{client, Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::io::beside::{self, beside, Backlog};
use crate::server::audit::Tally;
use crate::server::channel::Window;

/// How long the handler waits for the upstream's reply to a request: the
/// client's connection waits with it.
pub(super) const REPLY_LIMIT: Duration = Duration::from_secs(20);

/// The most bytes that each side keeps beside a write: the client's side
/// holds no more data than the window that the gateway gave, and the
/// upstream's no more than this before it holds the upstream back, as the
/// channel's queue did. Either side alone breaks the cycle.
const ASIDE: usize = 2 << 20;

/// The replies that may wait unread: the handler asks one at a time, so a
/// second one is a fault of the upstream, and is dropped.
const REPLIES: usize = 4;

/// One session channel of the client and its channel at the upstream.
pub(super) struct Pair {
    /// Where the handler sends each request of the client.
    pub(super) up: Arc<ChannelWriteHalf<client::Msg>>,
    replies: mpsc::Receiver<bool>,
}

/// What the upstream said to a request.
pub(super) enum Reply {
    Yes,
    No,
    /// No reply within [`REPLY_LIMIT`], or the channel is gone: the order of
    /// the replies is lost, so the pair must close.
    Lost(String),
}

impl Pair {
    /// Each reply that came with no request is a fault of the upstream:
    /// passed over before a request, so that it answers no later one.
    pub(super) fn forget_stray(&mut self) {
        while self.replies.try_recv().is_ok() {}
    }

    /// The reply to the request whose sending gave `sent`.
    pub(super) async fn reply(&mut self, sent: Result<(), russh::Error>) -> Reply {
        if let Err(e) = sent {
            return Reply::Lost(format!("the upstream's channel is gone ({})", podssh_ws::text::said(&e)));
        }
        match tokio::time::timeout(REPLY_LIMIT, self.replies.recv()).await {
            Ok(Some(true)) => Reply::Yes,
            Ok(Some(false)) => Reply::No,
            Ok(None) => Reply::Lost("the upstream's channel closed".into()),
            Err(_) => Reply::Lost(format!("the upstream did not answer within {} s", REPLY_LIMIT.as_secs())),
        }
    }
}

/// Carry the session channel `down` of the client and `up` of the upstream
/// both ways, from now until either closes; the handler gets the pair, to
/// forward each request.
pub(super) fn session(down: Channel<Down>, up: Channel<client::Msg>, handle: Handle) -> Pair {
    let (replies_in, replies) = mpsc::channel(REPLIES);
    let (up, _, _) = start(down, up, handle, Some(replies_in), Arc::default());
    Pair { up, replies }
}

/// Carry a `direct-tcpip` channel of the client and its channel at the
/// upstream both ways, until both sides ended; `tally` counts the bytes.
pub(super) async fn forward(down: Channel<Down>, up: Channel<client::Msg>, handle: Handle, tally: Arc<Tally>) {
    let (_, from_client, from_upstream) = start(down, up, handle, None, tally);
    let _ = from_client.await;
    let _ = from_upstream.await;
}

type Ends = (Arc<ChannelWriteHalf<client::Msg>>, JoinHandle<()>, JoinHandle<()>);

fn start(
    down: Channel<Down>,
    up: Channel<client::Msg>,
    handle: Handle,
    replies: Option<mpsc::Sender<bool>>,
    tally: Arc<Tally>,
) -> Ends {
    let (down_read, down_write) = down.split();
    let (up_read, up_write) = up.split();
    let up_write = Arc::new(up_write);
    let window = Window { handle: handle.clone(), id: down_write.id() };
    let from_client = tokio::spawn(from_client(down_read, up_write.clone(), window, tally.clone()));
    let from_upstream = tokio::spawn(from_upstream(up_read, down_write, handle, replies, tally));
    (up_write, from_client, from_upstream)
}

/// The client's side: its data to the upstream, each chunk given back to
/// the client's window once the upstream's window took it; its EOF; its
/// close, which closes the upstream's channel too.
async fn from_client(
    mut read: ChannelReadHalf,
    up: Arc<ChannelWriteHalf<client::Msg>>,
    window: Window,
    tally: Arc<Tally>,
) {
    let mut aside = Backlog::with_most(ASIDE);
    while let Some(message) = beside::next(&mut read, &mut aside).await {
        match message {
            ChannelMsg::Data { data } => {
                let n = data.len();
                tally.took(n);
                if beside(up.data_bytes(data), &mut read, &mut aside, &|| {}).await.is_err() {
                    break;
                }
                window.grant(n);
            }
            // A client's extended data has no meaning in a session (RFC
            // 4254, section 5.2): given back, and carried nowhere.
            ChannelMsg::ExtendedData { data, .. } => window.grant(data.len()),
            ChannelMsg::Eof => {
                if beside(up.eof(), &mut read, &mut aside, &|| {}).await.is_err() {
                    break;
                }
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = beside(up.close(), &mut read, &mut aside, &|| {}).await;
}

/// The upstream's side: its data, its stderr, its EOF, its exit status or
/// signal and its close to the client, in the order they came; its replies
/// to the handler's queue.
async fn from_upstream(
    mut read: ChannelReadHalf,
    down: ChannelWriteHalf<Down>,
    handle: Handle,
    replies: Option<mpsc::Sender<bool>>,
    tally: Arc<Tally>,
) {
    let id = down.id();
    let mut aside = Backlog::with_most(ASIDE);
    while let Some(message) = beside::next(&mut read, &mut aside).await {
        let carried = match message {
            ChannelMsg::Data { data } => {
                tally.gave(data.len());
                beside(down.data_bytes(data), &mut read, &mut aside, &|| {}).await.is_ok()
            }
            // Stderr; any other code has no meaning (RFC 4254, 5.2).
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                tally.gave(data.len());
                beside(down.extended_data_bytes(1, data), &mut read, &mut aside, &|| {}).await.is_ok()
            }
            ChannelMsg::Eof => beside(down.eof(), &mut read, &mut aside, &|| {}).await.is_ok(),
            ChannelMsg::ExitStatus { exit_status } => {
                beside(down.exit_status(exit_status), &mut read, &mut aside, &|| {}).await.is_ok()
            }
            ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, lang_tag } => {
                let signal = handle.exit_signal_request(id, signal_name, core_dumped, error_message, lang_tag);
                beside(signal, &mut read, &mut aside, &|| {}).await.is_ok()
            }
            ChannelMsg::Success => answered(replies.as_ref(), true),
            ChannelMsg::Failure => answered(replies.as_ref(), false),
            ChannelMsg::Close => break,
            _ => true,
        };
        if !carried {
            break;
        }
    }
    let _ = beside(down.close(), &mut read, &mut aside, &|| {}).await;
}

/// A reply of the upstream to the handler's queue, where there is one. A
/// full queue is an upstream that answered unasked: the reply is dropped.
fn answered(replies: Option<&mpsc::Sender<bool>>, yes: bool) -> bool {
    if let Some(replies) = replies {
        let _ = replies.try_send(yes);
    }
    true
}
