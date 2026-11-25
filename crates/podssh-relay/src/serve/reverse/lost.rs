//! How the role finds a node's socket dead with no word from it: a link lost
//! with no reset (a NAT that forgot it, a host that went away). A node that
//! comes back meets `409` while the role holds its lost socket, and gives
//! the route up after a minute of them (`pod-relay`'s `Settings::lost_hold`);
//! each operator meanwhile reaches the dead socket and stops. So the role
//! frees the name well within that minute.

use std::time::Duration;

use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite};

/// The role pings a node's socket this often, the node's own interval.
pub const EVERY: Duration = Duration::from_secs(10);
/// So many intervals in a row with nothing heard after a Ping: between 30 s
/// and 40 s of silence, under the node's minute of `409`. A live node pings
/// the role each 10 s itself, so it is heard even behind a long write.
pub const ALLOWED: u32 = 3;

/// Until nothing came from the node's `session` for `allowed` intervals of
/// `every` in a row since the role's first Ping, or a Ping could not be
/// written; the words of the loss. Unlike the client's watch, it waits for no
/// first Pong: a node is a WebSocket client, which RFC 6455 has answer each
/// Ping, and a node lost before its first Pong would else hold its name
/// until the kernel gives the connection up, many minutes later.
pub async fn silent<S>(session: &RelaySession<S>, every: Duration, allowed: u32) -> String
where
    S: AsyncRead + AsyncWrite,
{
    let mut heard = session.frames_received();
    let (mut missed, mut sent) = (0u32, 0u64);
    loop {
        tokio::time::sleep(every).await;
        let now = session.frames_received();
        if now > heard {
            heard = now;
            missed = 0;
        } else if sent > 0 {
            missed += 1;
        }
        if missed >= allowed {
            let quiet = every.as_secs() * u64::from(allowed);
            return format!("nothing from the node for {quiet} s, pings unanswered: its link was lost");
        }
        sent += 1;
        if let Err(e) = session.send_ping(&sent.to_be_bytes()).await {
            return format!("a ping to the node failed: {}", podssh_ws::text::said(&e));
        }
    }
}

#[cfg(test)]
#[path = "lost_tests.rs"]
mod tests;
