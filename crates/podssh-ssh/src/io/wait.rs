//! The waits of the session's loop that are for ever with nothing to wait
//! for, apart from `io.rs` so that each file stays short.

use crate::elevate::{Elevated, Next};
use crate::expect::Expect;

/// An elevated command's question and time (T-032): its answer, or its time
/// that ran out; for ever with none.
pub(super) async fn elevating(elevated: &mut Option<Elevated>) -> Next {
    match elevated {
        Some(e) => e.next().await,
        None => std::future::pending().await,
    }
}

/// Until the expect rule that waits runs out of time: the words of its
/// miss; for ever with none (T-191).
pub(super) async fn expecting(expect: Option<&Expect>) -> String {
    match expect {
        Some(x) => x.missed().await,
        None => std::future::pending().await,
    }
}

/// A keepalive that asks for a reply, as russh sends it (T-332).
pub(super) type Ping<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), russh::Error>> + Send + 'a>>;

/// Until the server replies to the keepalive; for ever with none. A reply
/// of failure, from a server that knows no such request, is a reply too.
pub(super) async fn answered(ping: &mut Option<Ping<'_>>) {
    match ping {
        Some(ping) => {
            let _ = ping.as_mut().await;
        }
        None => std::future::pending().await,
    }
}

/// Until `at`, or for ever with none.
pub(super) async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
