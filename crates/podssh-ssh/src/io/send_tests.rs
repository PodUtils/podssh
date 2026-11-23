//! A send whose write waits for the channel's window lock goes on once the
//! lock is free, also after T-598's probe of the window ran meanwhile
//! (T-859). tokio's lock takes its permit, then yields when the task's budget
//! is spent: a write can hold the lock while it is not polled. The probe
//! awaited in a branch's body, as it was, then queued behind that write,
//! which waited for the body to end: the pump and russh's loop stopped for
//! good, 4 of 90 uploads of a plain `rz`. Both ends are in this process.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::Channel;

use super::{send, Also};
use crate::io::beside::Backlog;
use crate::io::busy::Busy;
use crate::io::{Out, Through};
use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};
use crate::terminal::termination::Termination;

/// Lets anyone in, opens a session channel, and drops what comes.
struct Drops;

impl server::Handler for Drops {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
}

/// Poll `fut` once with the task's budget spent: a lock that it awaits is
/// taken, and held while the future waits.
async fn poll_spent<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    std::future::poll_fn(|cx| {
        // Each new `consume_budget` takes one unit; the first that finds
        // none is pending, and the budget is spent. A bound, should the
        // runtime keep no budget.
        for _ in 0..10_000 {
            let mut spend = Box::pin(tokio::task::coop::consume_budget());
            if spend.as_mut().poll(cx).is_pending() {
                break;
            }
        }
        assert!(!tokio::task::coop::has_budget_remaining(), "the task's budget is spent");
        Poll::Ready(Pin::new(&mut *fut).poll(cx))
    })
    .await
}

#[tokio::test]
async fn a_send_goes_on_once_the_window_lock_is_free_after_the_probe_ran() {
    let test = async {
        let (client_end, server_end) = tokio::io::duplex(1 << 16);
        let mut config = server::Config::default();
        config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let config = Arc::new(config);
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, server_end, Drops).await {
                let _ = session.await;
            }
        });
        let dir = std::env::temp_dir().join(format!("podssh-send-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let hop = Hop { user: Some("podtest".into()), host: "lock.test".into(), port: 22, tls: false };
        let mut opts = Options::new(hop.clone(), "podtest".into());
        opts.connect_timeout = Duration::from_secs(10);
        opts.strict_host_key_checking = StrictHostKeyChecking::No;
        opts.user_known_hosts = vec![dir.join("known_hosts")];
        opts.agent = Agent::Off;
        opts.batch_mode = true;
        let log = Log::new(LogLevel::Quiet);
        let client = crate::run::connect(client_end, &hop, true, &opts, &Arc::new(Log::new(LogLevel::Quiet)))
            .await
            .expect("logged in");
        let _ = std::fs::remove_dir_all(&dir);
        let channel = client.channel_open_session().await.expect("a session channel");
        let (mut reader, writer) = channel.split();
        let mut through = Through { window_stall: true, ..Through::default() };
        let (mut out, mut status, mut aside) = (Out::default(), None, Backlog::default());
        let mut stop = Termination::new(false, None);
        // The select's order is random: with the probe first, the old body
        // passed by luck; eight rounds leave it one chance in 256.
        for round in 0..8 {
            let mut hold = Box::pin(writer.data_bytes(vec![b'h'; 16]));
            assert!(poll_spent(&mut hold).await.is_pending(), "round {round}: the held write waits");
            // A new turn of the task: a budget of its own.
            tokio::task::yield_now().await;
            let also = Also { stop: &mut stop, zmodem: None };
            let state = (&mut status, &mut out, &mut through);
            let busy = Busy::default();
            let sending = send(&writer, (&mut reader, &mut aside), b"next".to_vec(), state, also, &busy, &log);
            tokio::pin!(sending);
            // The probe's first tick comes at once, while the lock is held.
            tokio::select! {
                _ = &mut sending => panic!("round {round}: the send went while the lock was held"),
                () = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
            drop(hold);
            let sent = tokio::time::timeout(Duration::from_secs(5), sending).await;
            assert!(matches!(sent, Ok(Ok(true))), "round {round}: the send went once the lock was free");
        }
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("within 60 s");
}
