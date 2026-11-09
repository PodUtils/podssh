//! What a road does at the end of this side's input (T-699). A WebSocket
//! has no half-close: a peer may answer a Close at once and send nothing
//! after it (RFC 6455, section 5.5.1), and a Wisp stream's CLOSE drops what
//! is still on its way. So a road whose session is done at that end (an SSH
//! session's) closes at once, and one whose target may still answer (a
//! pipe) closes only after the peer's end. Each carrier of these roads asks
//! [`end_of_input`], so that no road derives the rule again, and each road
//! names its choice in its `Dial`, which has no default.

use std::future::Future;

/// What the end of this side's input does to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtEnd {
    /// The session is done: the carrier closes at once (an SSH session).
    Now,
    /// The target may still answer: the carrier closes only once the peer
    /// ended (a pipe).
    AfterPeer,
}

/// The end of this side's input: `close` at once, or once `peer_ended`
/// came. No timer: the wait is the peer's, as a timer waits for a
/// measurement of the public relay.
pub(crate) async fn end_of_input(at: AtEnd, peer_ended: impl Future<Output = ()>, close: impl Future<Output = ()>) {
    if at == AtEnd::AfterPeer {
        peer_ended.await;
    }
    close.await;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    /// `Now` closes with the peer still open; `AfterPeer` closes only after
    /// the peer's end, and not before it.
    #[tokio::test]
    async fn now_closes_at_once_and_after_peer_waits_for_the_peer() {
        let closed = AtomicBool::new(false);
        let close = async { closed.store(true, Ordering::SeqCst) };
        let at_once = end_of_input(AtEnd::Now, std::future::pending::<()>(), close);
        tokio::time::timeout(Duration::from_secs(5), at_once).await.expect("no wait for the peer");
        assert!(closed.load(Ordering::SeqCst));

        let (peer, ended) = tokio::sync::oneshot::channel::<()>();
        let closed = AtomicBool::new(false);
        let close = async { closed.store(true, Ordering::SeqCst) };
        let waiting = end_of_input(AtEnd::AfterPeer, async { ended.await.unwrap() }, close);
        tokio::pin!(waiting);
        let early = tokio::time::timeout(Duration::from_millis(200), &mut waiting).await;
        assert!(early.is_err() && !closed.load(Ordering::SeqCst), "closed before the peer's end");
        peer.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("the close after the peer's end");
        assert!(closed.load(Ordering::SeqCst));
    }
}
