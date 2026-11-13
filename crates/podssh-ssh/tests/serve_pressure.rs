//! A slow client and a slow child of `podssh serve` (T-118), with russh's
//! client over a pipe in memory: `yes` on pipes and on a pty, with a client
//! that reads nothing for 20 s, grows the process's resident memory by less
//! than 8 MiB, and the session then goes on; a closed channel ends `yes`
//! within 5 s. A child that reads nothing of a client's 32 MiB holds its own
//! channel alone: a command beside it, on the same connection, runs to its
//! end.
//!
//! The memory is this process's, the client's buffers with the server's,
//! measured from before the command starts: the client holds 8 messages of
//! a channel (256 KiB) and the pipe between the two ends 4 MiB, so a server
//! that holds a window and a read buffer stays far under the bound, and one
//! that reads its child faster than it sends passes it within a second.
//! Each test takes one lock, so that no other test's memory is counted.

#![cfg(unix)]

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel, ChannelMsg};
use podssh_ssh::server::{self, pty, Authorized, Settings};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);
/// How long the client reads nothing.
const STALL: Duration = Duration::from_secs(20);
/// The growth of the resident memory allowed while it reads nothing.
const BOUND_KIB: u64 = 8 * 1024;

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// One measurement of memory at a time in this process.
fn measuring() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// This process's resident memory in KiB, where `/proc` tells it.
fn resident_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a new server, with this host's PATH; the
/// client holds 8 messages of each channel, not russh's 100.
async fn connect() -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a small pipe stop
    // each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let settings = Settings { base_env: Some(vec![("PATH".into(), path)]), ..Settings::default() };
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let config = client::Config { channel_buffer_size: 8, ..client::Config::default() };
    let mut handle = client::connect_stream(Arc::new(config), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// The pid that the command says on its first line, and the bytes of
/// output read with it.
async fn first_line(channel: &mut Channel<client::Msg>) -> (i32, usize) {
    let mut out = Vec::new();
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                out.extend_from_slice(&data);
                if let Some(end) = out.iter().position(|b| *b == b'\n') {
                    let pid = String::from_utf8_lossy(&out[..end]).trim().parse().expect("a pid");
                    return (pid, out.len());
                }
            }
        }
        panic!("the channel ended before its first line");
    })
    .await
    .expect("the first line in time")
}

/// The bytes of data that come within `time`.
async fn read_for(channel: &mut Channel<client::Msg>, time: Duration) -> usize {
    let mut got = 0;
    let _ = tokio::time::timeout(time, async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                got += data.len();
            }
        }
    })
    .await;
    got
}

fn runs(pid: i32) -> bool {
    // SAFETY: kill with 0 sends nothing; it only asks.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// `yes` on a new channel (on a pty when `on_pty`), a client that reads
/// nothing of it for [`STALL`]: the growth of the memory stays under the
/// bound, the session then goes on, and a close ends `yes`.
async fn yes_with_a_stalled_client(on_pty: bool) {
    let _one = measuring().lock().await;
    let handle = connect().await;
    let mut channel = handle.channel_open_session().await.unwrap();
    if on_pty {
        channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let Some(before) = resident_kib() else {
        eprintln!("did not measure: no /proc/self/status here");
        return;
    };
    channel.exec(true, "echo $$; exec yes").await.unwrap();
    let (pid, _) = first_line(&mut channel).await;
    let mut most = resident_kib().unwrap_or(before);
    let started = Instant::now();
    while started.elapsed() < STALL {
        tokio::time::sleep(Duration::from_secs(1)).await;
        most = most.max(resident_kib().unwrap_or(most));
    }
    let grew = most.saturating_sub(before);
    assert!(grew < BOUND_KIB, "the memory grew by {grew} KiB while the client read nothing (pty: {on_pty})");
    assert!(runs(pid), "yes waits on its full output, it is not ended");
    let more = read_for(&mut channel, Duration::from_secs(2)).await;
    assert!(more > 1 << 20, "the session goes on after the stall: {more} bytes in 2 s");
    channel.close().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while runs(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!runs(pid), "yes runs on after its channel closed (pty: {on_pty})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yes_on_pipes_with_a_client_that_reads_nothing_holds_the_memory() {
    yes_with_a_stalled_client(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yes_on_a_pty_with_a_client_that_reads_nothing_holds_the_memory() {
    if let Err(why) = pty::open() {
        eprintln!("did not run: no pty here: {why}");
        return;
    }
    yes_with_a_stalled_client(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_child_that_reads_nothing_holds_no_other_channel() {
    let _one = measuring().lock().await;
    let handle = connect().await;
    let deaf = handle.channel_open_session().await.unwrap();
    deaf.exec(true, "exec sleep 60").await.unwrap();
    // 32 MiB at a child that reads none: more than each queue of both ends.
    let sending = tokio::spawn(async move {
        let big = vec![b'x'; 32 << 20];
        let _ = deaf.data(&big[..]).await;
        deaf
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ran = tokio::time::timeout(Duration::from_secs(10), async {
        // The open too: a connection that waits on the deaf channel
        // answers no open.
        let mut beside = handle.channel_open_session().await.unwrap();
        beside.exec(true, "echo beside").await.unwrap();
        let mut out = Vec::new();
        while let Some(message) = beside.wait().await {
            match message {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        out
    })
    .await;
    let out = ran.expect("a channel beside a child that reads nothing runs to its end");
    assert_eq!(out, b"beside\n");
    assert!(!sending.is_finished(), "the client waits on the deaf channel's window alone");
    sending.abort();
}
