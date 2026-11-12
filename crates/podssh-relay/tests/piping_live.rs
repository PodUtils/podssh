//! The Piping Server road against `https://ppng.io` (T-437), live and short,
//! as the operator's ruling Q65 allows: a node and a client in this process,
//! through the proxy of the environment, with a key of this run's so that
//! no other run meets these paths; a session of the resumable layer carries
//! 64 KiB each way through a node in front of an echo. `PODSSH_PIPING` names
//! another server.
//!
//! The rates (T-625): three sessions through each public server, 4 MiB each
//! way at once, the streamed form through `ppng.io` and the numbered pieces
//! through the server that holds a body to its end, as podssh uses each; a
//! session's open is timed apart, by one byte echoed first. Short (Q65, Q88).
//!
//!     cargo test -p podssh-relay --features piping --test piping_live -- --ignored --nocapture

#![cfg(feature = "piping")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::piping::{self as road, dial, Dialer, Http, Node, Secret, Server};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{Entropy, OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SIZE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(120);
/// The bytes of a run of the rates, each way.
const RATE_SIZE: usize = 4 * 1024 * 1024;
/// A run of the rates: 4 MiB at the archive's 0.12 MiB/s, and its open.
const RATE_LIMIT: Duration = Duration::from_secs(240);

async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: ppng.io, or the server of PODSSH_PIPING, through the proxy of the environment"]
async fn a_session_through_ppng_io_carries_64_kib_each_way() {
    let server = match std::env::var("PODSSH_PIPING").ok().filter(|v| v.starts_with("https://")) {
        Some(url) => Server::parse(&url).expect("PODSSH_PIPING names a server"),
        None => Server::default(),
    };
    eprintln!("server: {server}");
    let mut key = [0u8; 32];
    OsEntropy.fill(&mut key).expect("random bytes");
    let secret = || Secret::from_bytes(key);
    let http = || Http::new(server.clone(), dial::tls(Trust::Default, ProxyChoice::FromEnvironment));
    let say = |who: &'static str| -> road::Say { Arc::new(move |line: String| eprintln!("{who}: {line}")) };
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let node = Node { secret: Arc::new(secret()), http: Arc::new(http()), fallbacks: Vec::new(), say: say("node") };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, 64 << 20, echo, keeper));
    let dialer = Dialer::new(secret(), http(), say("client"));
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let mut back = vec![0u8; SIZE];
        let ((), ()) =
            tokio::join!(async { writer.write_all(&out).await.expect("the layer takes the bytes") }, async {
                reader.read_exact(&mut back).await.map(|_| ()).expect("the echo")
            },);
        drop((reader, writer));
        back
    };
    let both = async { tokio::join!(road::carry(&dialer, app, settings, |_| {}), using) };
    let (carried, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&out), "each byte came back once, in order");
    carried.expect("the session ran");
    eprintln!("protocol: {:?}; numbered pieces: {}", dialer.proto(), dialer.numbered());
    serving.abort();
    dialer.close().await;
}

/// One run of the rates through `server`: the open (one byte echoed), the
/// time of [`RATE_SIZE`] each way at once after it, and whether the links
/// were numbered; or why the run did not end.
async fn rate_run(server: &Server) -> Result<(f64, f64, bool), String> {
    let mut key = [0u8; 32];
    OsEntropy.fill(&mut key).expect("random bytes");
    let secret = || Secret::from_bytes(key);
    let http = || Http::new(server.clone(), dial::tls(Trust::Default, ProxyChoice::FromEnvironment));
    let say = |who: &'static str| -> road::Say { Arc::new(move |line: String| eprintln!("{who}: {line}")) };
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let node = Node { secret: Arc::new(secret()), http: Arc::new(http()), fallbacks: Vec::new(), say: say("node") };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, 64 << 20, echo, keeper));
    let dialer = Dialer::new(secret(), http(), say("client"));
    let (app, user) = tokio::io::duplex(1024 * 1024);
    let out: Vec<u8> = (0..RATE_SIZE).map(|i| (i % 251) as u8).collect();
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let began = std::time::Instant::now();
        writer.write_all(&[7]).await.map_err(|e| format!("the first byte: {e}"))?;
        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.map_err(|e| format!("the first byte's echo: {e}"))?;
        let opened = began.elapsed().as_secs_f64();
        let began = std::time::Instant::now();
        let mut back = vec![0u8; RATE_SIZE];
        let (wrote, read) = tokio::join!(writer.write_all(&out), reader.read_exact(&mut back));
        wrote.map_err(|e| format!("the bytes out: {e}"))?;
        read.map_err(|e| format!("the echo: {e}"))?;
        let carried = began.elapsed().as_secs_f64();
        assert_eq!(Sha256::digest(&back), Sha256::digest(&out), "each byte came back once, in order");
        drop((reader, writer));
        Ok::<_, String>((opened, carried))
    };
    let both = async { tokio::join!(road::carry(&dialer, app, settings, |_| {}), using) };
    // On the heap: the session's future is larger than a test thread's stack.
    let ended = tokio::time::timeout(RATE_LIMIT, Box::pin(both)).await;
    let numbered = dialer.numbered();
    serving.abort();
    dialer.close().await;
    let (session, used) = ended.map_err(|_| format!("no end within {} s", RATE_LIMIT.as_secs()))?;
    let (opened, carried) = used.map_err(|why| format!("{why}; the session: {session:?}"))?;
    Ok((opened, carried, numbered))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: the public Piping Servers, through the proxy of the environment"]
async fn the_rates_of_both_forms_through_the_public_servers() {
    let mut ended = 0;
    for server in road::server::public() {
        for run in 1..=3 {
            let (opened, carried, numbered) = match Box::pin(rate_run(&server)).await {
                Ok(run) => run,
                Err(why) => {
                    // A measurement too: the server's other runs would wait as long.
                    eprintln!("RATE {server} run {run}: {why}");
                    break;
                }
            };
            ended += 1;
            let form = if numbered { "numbered pieces" } else { "streamed" };
            let rate = RATE_SIZE as f64 / (1024.0 * 1024.0) / carried;
            eprintln!(
                "RATE {server} {form} run {run}: open {opened:.2} s; 4 MiB each way at once in {carried:.2} s, \
                 {rate:.3} MiB/s each way"
            );
        }
    }
    assert!(ended > 0, "no run through any public server ended");
}
