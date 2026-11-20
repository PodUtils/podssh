//! The step that the SSH session's loop awaits in (T-780, podssh's patch of
//! russh, `russh::client::Step`). A server of this process floods a channel
//! that the client does not read: russh's loop then waits on the channel's
//! full queue and reads nothing of its stream, and its step must say so.
//! Once the client reads the channel, the loop goes back to its select.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::run::connect_hops;
use podssh_ssh::{Agent, Hop, Log, LogLevel, Options, StrictHostKeyChecking};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelMsg};

/// The flood: more chunks than a channel's queue and its window hold.
const CHUNK: usize = 16 << 10;
const CHUNKS: usize = 2000;

struct Flood;

impl server::Handler for Flood {
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

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let handle = session.handle();
        tokio::spawn(async move {
            for _ in 0..CHUNKS {
                if handle.data(channel, vec![b'x'; CHUNK]).await.is_err() {
                    return;
                }
            }
        });
        Ok(())
    }
}

fn options() -> Options {
    let hop = Hop { user: Some("podtest".into()), host: "flood.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop, "podtest".to_string());
    opts.connect_timeout = Duration::from_secs(10);
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identities_only = true;
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.log_level = LogLevel::Quiet;
    opts
}

/// The step after `within`, polled each 50 ms until `done` says it is the one.
async fn step_until(
    step: &russh::client::Step,
    within: Duration,
    done: impl Fn(Option<&'static str>) -> bool,
) -> Option<&'static str> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let now = step.now().map(|(_, what)| what);
        if done(now) || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_channel_that_nobody_reads_holds_the_loop_in_its_queue() {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Flood).await {
            let _ = session.await;
        }
    });
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let handles = tokio::time::timeout(Duration::from_secs(30), connect_hops(client_end, &options(), &log))
        .await
        .expect("logged in within 30 s")
        .expect("logged in to the stand-in");
    let handle = handles.last().expect("the destination");
    let step = handle.step();
    assert_eq!(step.now().map(|(_, what)| what), None, "a loop in its select is in no step");
    let mut channel = handle.channel_open_session().await.expect("a session channel");
    channel.exec(true, "flood").await.expect("the exec sent");

    // Nobody reads the channel: the loop waits on its full queue.
    let queue = "the queue of a channel, with its CHANNEL_DATA";
    let held = step_until(&step, Duration::from_secs(20), |now| now == Some(queue)).await;
    assert_eq!(held, Some(queue), "the loop is held in the channel's queue");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(step.now().map(|(_, what)| what), Some(queue), "and stays there while nobody reads");

    // The channel read: the loop leaves the queue.
    let mut read = 0usize;
    let left = tokio::time::timeout(Duration::from_secs(20), async {
        while read < 64 * CHUNK {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => read += data.len(),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert!(left.is_ok(), "the channel gave {read} bytes within 20 s");
    assert!(read >= 64 * CHUNK, "the channel gave {read} bytes");
    podssh_ssh::run::disconnect_all(&handles).await;
}
