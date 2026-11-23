//! A ZMODEM upload through the session's pump to a far `rz` that stops
//! reading (T-859), a module of `tests/zmodem.rs`. A russh server of this
//! process plays `rz`: it prints its start, answers ZFILE with ZRPOS 0, and
//! then reads nothing more, so the channel's window shuts and podssh's write
//! of the file waits for good. The road resumes no link, so no stall of the
//! window ends the session (`window_stall` off): before T-859 the pump then
//! waited in that write, deaf to its keys and its time. Now the transfer
//! ends at the write's limit, at Ctrl-C, at five CAN typed, and with the end
//! of the local input, which ends the session too; each says one line.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::io::{self, End, Feed, Input, Through};
use podssh_ssh::run::{connect_hops, disconnect_all};
use podssh_ssh::zmodem::wire::{self, Event, Reader};
use podssh_ssh::zmodem::Zmodem;
use podssh_ssh::{Agent, Hop, Log, LogLevel, Options, StrictHostKeyChecking};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::{mpsc, Notify};

use super::cleanup;

/// The far `rz`: its start, ZRPOS 0 for ZFILE, then nothing read.
struct StopsReading {
    reader: Reader,
    asked: bool,
    stopped: Arc<Notify>,
}

impl server::Handler for StopsReading {
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

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut ServerSession) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let mut start = b"rz waiting to receive.".to_vec();
        start.extend(wire::hex_header(wire::ZRINIT, [0, 0, 0, 0x23]));
        session.data(channel, start)
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut ServerSession) -> Result<(), Self::Error> {
        if self.asked {
            // The file's data comes: from here on nothing is read, and the
            // server's loop with it, as a far end whose tty takes no more.
            self.stopped.notify_one();
            std::future::pending::<()>().await;
        }
        for &byte in data {
            if let Some(Event::Data { end: wire::ZCRCW, .. }) = self.reader.push(byte) {
                self.asked = true;
                session.data(channel, wire::hex_header(wire::ZRPOS, wire::at(0)))?;
            }
        }
        Ok(())
    }
}

fn options() -> Options {
    let hop = Hop { user: Some("podtest".into()), host: "rz.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop, "podtest".to_string());
    opts.connect_timeout = Duration::from_secs(10);
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identities_only = true;
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.log_level = LogLevel::Quiet;
    opts
}

/// What ends the upload, after the far end stopped.
#[derive(Debug, Clone, Copy, PartialEq)]
enum How {
    Limit,
    CtrlC,
    Can,
    Hangup,
}

/// The file to send: more than the far end's window and the pipe hold.
fn upload_file(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-zmodem-pump-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    let path = dir.join("up.bin");
    std::fs::write(&path, (0..(1u32 << 20)).map(|i| (i * 7) as u8).collect::<Vec<u8>>()).expect("a file");
    path
}

/// One upload that `how` ends: what the terminal showed, and how the
/// session ended, if it did within the test's wait.
async fn upload(how: How) -> (String, Option<End>) {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.window_size = 64 * 1024;
    let config = Arc::new(config);
    let stopped = Arc::new(Notify::new());
    let far = StopsReading { reader: Reader::new(), asked: false, stopped: stopped.clone() };
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, far).await {
            let _ = session.await;
        }
    });
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let handles = connect_hops(client_end, &options(), &log).await.expect("logged in to the far rz");
    let handle = handles.last().expect("the destination");
    let channel = handle.channel_open_session().await.expect("a session channel");
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.expect("a pty");
    channel.request_shell(true).await.expect("a shell");

    let path = upload_file(&format!("{how:?}"));
    // The keys' limit is long, so that only the key can end those rows.
    let limit = if how == How::Limit { Duration::from_secs(2) } else { Duration::from_secs(600) };
    let (sink, mut shown) = mpsc::channel(64);
    let through = Through {
        zmodem: Some(Zmodem::new().with_limit(limit)),
        sink: Some(sink),
        window_stall: false,
        ..Through::default()
    };
    let feed = Feed::new();
    let mut input = Input::fed(feed.clone());
    let pump = io::pump(handle, channel, Vec::new(), None, true, &mut input, through, None, &log);
    tokio::pin!(pump);
    let mut screen = String::new();
    let mut ended = None;
    let drive = async {
        let (mut acted, mut answered) = (false, false);
        loop {
            tokio::select! {
                got = shown.recv() => match got {
                    Some((bytes, _)) => screen.push_str(&String::from_utf8_lossy(&bytes)),
                    None => return,
                },
                () = stopped.notified(), if !acted => {
                    acted = true;
                    // The pump fills the window, then waits in its write.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    match how {
                        How::Limit => {}
                        How::CtrlC => {
                            feed.put(b"\x03");
                        }
                        How::Can => {
                            feed.put(b"\x18\x18");
                            feed.put(b"\x18\x18\x18");
                        }
                        How::Hangup => feed.end(),
                    }
                }
            }
            if !answered && screen.contains("Send which file?") {
                answered = true;
                feed.put(format!("{}\r", path.display()).as_bytes());
            }
            if screen.contains("podssh: ZMODEM: ") && screen.ends_with("\r\n") {
                return;
            }
        }
    };
    tokio::select! {
        end = &mut pump => ended = Some(end),
        _ = tokio::time::timeout(Duration::from_secs(20), drive) => {}
    }
    // What the pump said as it ended.
    while let Ok((bytes, _)) = shown.try_recv() {
        screen.push_str(&String::from_utf8_lossy(&bytes));
    }
    disconnect_all(&handles).await;
    (screen, ended)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_rz_that_stops_reading_ends_at_the_limit_the_keys_and_the_terminals_end() {
    let rows = [
        (How::Limit, Some("podssh: ZMODEM: the server took nothing that podssh sent for 2 s\r\n")),
        (How::CtrlC, Some("podssh: ZMODEM: cancelled here (Ctrl-C)\r\n")),
        (How::Can, Some("podssh: ZMODEM: cancelled here (CAN)\r\n")),
        // The terminal is gone: the session ends, and its words go nowhere.
        (How::Hangup, None),
    ];
    for (how, line) in rows {
        let started = std::time::Instant::now();
        let (screen, ended) =
            tokio::time::timeout(Duration::from_secs(60), upload(how)).await.expect("the test's wait");
        let took = started.elapsed();
        assert!(screen.contains("Send which file?"), "{how:?}: the question came: {screen:?}");
        match line {
            Some(line) => {
                assert_eq!(screen.matches("ZMODEM:").count(), 1, "{how:?}: one line: {screen:?}");
                assert!(screen.contains(line), "{how:?}: {line:?} in {screen:?}");
                assert!(ended.is_none(), "{how:?}: the session goes on: {ended:?}");
            }
            None => assert!(matches!(ended, Some(End::Terminated)), "{how:?}: the session ended: {ended:?}"),
        }
        assert!(took < Duration::from_secs(20), "{how:?}: ended in {took:?}");
    }
}
