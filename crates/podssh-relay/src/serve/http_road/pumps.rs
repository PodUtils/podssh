//! The target of a session of the HTTP road: its bytes read into the
//! session's window down, which bounds them, and the batches up written to
//! it in order, each once; after the last batch, TCP's half-close, which
//! the WebSocket road cannot give. Each write waits for the target, so a
//! slow target fills the window up, and the client's next batch waits.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::sessions::{self, Session, DOWN_WINDOW};

/// The bytes asked of the target in each read.
const READ: usize = 64 * 1024;

/// The tasks of `session`'s target `tcp`, and of its limits.
pub fn start(session: &Arc<Session>, tcp: TcpStream) {
    let (from, to) = tcp.into_split();
    let writer = tokio::spawn(write_up(session.clone(), to));
    let reader = tokio::spawn(read_down(session.clone(), from));
    tokio::spawn(sessions::watch(session.clone()));
    session.set_tasks(vec![writer.abort_handle(), reader.abort_handle()]);
}

/// What the writer does next.
enum Step {
    Stop,
    Wait,
    Write(Vec<u8>),
    Finish,
}

async fn write_up(session: Arc<Session>, mut to: OwnedWriteHalf) {
    let cap = session.cfg.limits.bytes;
    loop {
        let notified = session.changed.notified();
        let step = session.with(|st| {
            if st.ended.is_some() {
                Step::Stop
            } else if let Some(batch) = st.up.take() {
                // In number order: the window holds each batch by its number.
                Step::Write(batch)
            } else if st.up.fin() {
                Step::Finish
            } else {
                Step::Wait
            }
        });
        match step {
            Step::Stop => return,
            Step::Wait => notified.await,
            Step::Finish => {
                let _ = to.shutdown().await;
                return;
            }
            Step::Write(batch) => {
                // The cap is the pump's own, as on the forward road (T-732).
                let take = session.with(|st| {
                    let take = (batch.len() as u64).min(cap.saturating_sub(st.moved)) as usize;
                    st.moved += take as u64;
                    take
                });
                if let Err(e) = to.write_all(&batch[..take]).await {
                    return session.end(1011, format!("write failed: {e}"));
                }
                session.meter.up(take);
                session.with(|st| {
                    st.written += 1;
                    if !batch.is_empty() {
                        st.heard = Instant::now();
                    }
                });
                session.changed.notify_waiters();
                if take < batch.len() {
                    return session.end(1009, "session byte cap");
                }
            }
        }
    }
}

async fn read_down(session: Arc<Session>, mut from: OwnedReadHalf) {
    let cap = session.cfg.limits.bytes;
    let mut buf = vec![0u8; READ];
    loop {
        // Room first: the target waits while its bytes wait for the client.
        loop {
            let notified = session.changed.notified();
            let room = session.with(|st| st.ended.is_none().then_some(st.down.len() < DOWN_WINDOW));
            match room {
                None => return,
                Some(true) => break,
                Some(false) => notified.await,
            }
        }
        match from.read(&mut buf).await {
            Ok(0) => {
                session.with(|st| st.target_ended = true);
                session.changed.notify_waiters();
                return;
            }
            Ok(n) => {
                // The client's due, whether or not it fetches them, up to
                // the cap, which ends the session (T-732).
                let take = session.with(|st| {
                    let take = (n as u64).min(cap.saturating_sub(st.moved)) as usize;
                    st.down.extend(&buf[..take]);
                    st.moved += take as u64;
                    st.heard = Instant::now();
                    take
                });
                session.meter.down(take);
                session.changed.notify_waiters();
                if take < n {
                    return session.end(1009, "session byte cap");
                }
            }
            Err(e) => return session.end(1011, format!("target read failed: {e}")),
        }
    }
}
