//! The smee.io road (T-741) of the library that `podssh node` and `podssh
//! ssh node://` run: a session of the resumable layer carries 1 MiB each way
//! through a node in front of an echo, with equal digests, through a
//! stand-in of smee.io's server on the loopback (`smee_stand_in`), and
//! through smee.io's own server (probot/smee.io, run by
//! `.github/workflows/smee-interop.yml` at its pinned commit) where
//! `PODSSH_TEST_SMEE_URL` names it, behind the proxy of
//! `PODSSH_TEST_SMEE_PROXY` when one is named. The planted defect of the
//! entry, both ways of a link on one channel, makes each end read its own
//! frames, which the reader names. A client of another pair finds no node
//! at its door. `PODSSH_TEST_SMEE_LIVE=yes` runs the short live measurement
//! of Q94 through the server of `pod-services`, with throwaway channels.
//!
//!     cargo test -p podssh-cli --test smee_road
//!     PODSSH_TEST_SMEE_URL=http://127.0.0.1:3000 cargo test -p podssh-cli --test smee_road -- --nocapture

mod smee_stand_in;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::piping::dial::{BoxIo, Dial, Dialing, Proto};
use podssh_relay::piping::Server;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::Note;
use podssh_relay::session::Settings;
use podssh_relay::smee::link::{self, Opening};
use podssh_relay::smee::names::{Ends, LinkId};
use podssh_relay::smee::{self as road, client::DOOR_LIMIT, frame, Dialer, Http, Node, Secret};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(240);
/// The replay buffers that a node keeps, at most, as a node of the CLI does.
const BUDGET: usize = 64 << 20;
const TOKEN: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr";

fn say(who: &'static str) -> road::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// Cleartext TCP to `at`, directly or through the HTTP proxy `proxy`, as a
/// server on the loopback serves no TLS.
fn plain(at: (String, u16), proxy: Option<String>) -> (Server, Dial) {
    let server = Server { host: at.0.clone(), port: at.1, prefix: String::new() };
    let choice = match proxy {
        Some(url) => ProxyChoice::Via(podssh_ws::proxy::Proxy::parse(&url).expect("PODSSH_TEST_SMEE_PROXY")),
        None => ProxyChoice::Direct,
    };
    let dial: Dial = Arc::new(move |server: &Server| -> Dialing {
        let (host, port, choice) = (server.host.clone(), server.port, choice.clone());
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&host, port, &choice, Duration::from_secs(10))
                .await
                .map_err(|e| format!("{host}:{port}: {e}"))?;
            Ok((Box::new(tcp) as BoxIo, Proto::H1))
        })
    });
    (server, dial)
}

/// The server under test: `PODSSH_TEST_SMEE_URL`'s (`http://HOST:PORT`),
/// else the stand-in.
fn under_test() -> (Server, Dial, Option<smee_stand_in::StandIn>) {
    let proxy = std::env::var("PODSSH_TEST_SMEE_PROXY").ok().filter(|v| !v.is_empty());
    if let Some(url) = std::env::var("PODSSH_TEST_SMEE_URL").ok().filter(|v| !v.is_empty()) {
        let rest = url.strip_prefix("http://").expect("PODSSH_TEST_SMEE_URL is http://HOST:PORT");
        let (host, port) = rest.trim_end_matches('/').rsplit_once(':').expect("a port");
        let (server, dial) = plain((host.to_string(), port.parse().expect("a port")), proxy);
        return (server, dial, None);
    }
    let stand_in = smee_stand_in::StandIn::start();
    let (server, dial) = plain(("127.0.0.1".into(), stand_in.port), None);
    (server, dial, Some(stand_in))
}

/// Bytes that a seed fixes (xorshift64*).
fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// An echo of each byte, as a node's target.
async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

/// A session through `server` to a node of the pair `pair` in front of an
/// echo: 1 MiB out, and each byte back, with equal digests; the time it
/// took.
async fn one_mib_each_way(server: Server, dial: Dial, pair: &str) -> Duration {
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let http = || Http::new(server.clone(), dial.clone());
    let node = Node { secret: Arc::new(Secret::of_pair(pair, TOKEN)), http: Arc::new(http()), say: say("node") };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, BUDGET, echo, keeper));
    let dialer = Dialer::new(Secret::of_pair(pair, TOKEN), http(), say("client"));
    let notes = Mutex::new(Vec::new());
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    let started = Instant::now();
    let carrying = Box::pin(road::carry(&dialer, app, settings, |note: Note| notes.lock().unwrap().push(note)));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.expect("the layer takes the bytes") };
        let reading = async {
            let mut back = Vec::with_capacity(out.len());
            let mut buf = vec![0u8; 64 * 1024];
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
            }
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        drop((reader, writer));
        back
    };
    let both = async { tokio::join!(carrying, using) };
    let (carried, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    let took = started.elapsed();
    assert_eq!(back.len(), MIB);
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    carried.expect("the session ran");
    serving.abort();
    dialer.close().await;
    eprintln!("notes: {:?}", notes.lock().unwrap());
    took
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_carries_1_mib_each_way_through_smee_s_server() {
    let (server, dial, _stand_in) = under_test();
    let shown = server.to_string();
    let took = one_mib_each_way(server, dial, "test-pair").await;
    let rate = (2 * MIB) as f64 / 1024.0 / took.as_secs_f64();
    eprintln!("MEASURE {shown}: 1 MiB each way in {} ms, {rate:.1} KiB/s both ways", took.as_millis());
}

/// The planted defect of T-741: a link whose two ways are one channel. Its
/// end reads its own mark back, and says so; a link of two channels reads
/// the far end's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_ways_on_one_channel_read_their_own_frames_and_the_reader_names_it() {
    let (server, dial, _stand_in) = under_test();
    let http = Http::new(server, dial);
    let secret = Secret::of_pair("planted-pair", TOKEN);
    let id = LinkId([9; 16]);
    let client = Ends::client(&secret, &id);
    let one = Ends { recv: client.send.clone(), ..client.clone() };
    let mut events = link::open_stream(&http, &one.recv).await.expect("smee's ready");
    link::send_mark(&http, &one).await.expect("the mark is posted");
    let read = link::read_mark(&mut events, &one, Duration::from_secs(10)).await;
    let why = match read {
        Err(Opening::Failed(why)) => why,
        other => panic!("one channel for both ways was not caught: {other:?}"),
    };
    assert!(why.contains("read its own mark") && why.contains("one channel"), "{why}");
    // The node's way, read by the client, as the road takes them.
    let node = Ends::node(&secret, &id);
    let mut events = link::open_stream(&http, &client.recv).await.expect("smee's ready");
    link::send_mark(&http, &node).await.expect("the node's mark is posted");
    link::read_mark(&mut events, &client, Duration::from_secs(10)).await.expect("the far end's mark");
    http.close().await;
}

/// A late reader gets nothing of what came before its stream: smee.io keeps
/// nothing, which the road's numbers and the layer repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_gets_no_event_from_before_it_opened() {
    let (server, dial, _stand_in) = under_test();
    let http = Http::new(server, dial);
    let channel = Secret::of_pair("late-pair", TOKEN).door();
    http.post(&channel, &frame::frame(1, b"before"), Duration::from_secs(10)).await.expect("the first POST");
    let mut events = link::open_stream(&http, &channel).await.expect("smee's ready");
    http.post(&channel, &frame::frame(2, b"after"), Duration::from_secs(10)).await.expect("the second POST");
    loop {
        let event = events.next(Duration::from_secs(10)).await.expect("an event").expect("the stream goes on");
        if event.name == "message" {
            assert_eq!(frame::read(&event.data), Ok(frame::Message::Frame(2, b"after".to_vec())));
            break;
        }
    }
    http.close().await;
}

/// A client of another pair knocks at a door where no node waits, and is
/// told so within the door's limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_of_another_pair_finds_no_node_at_its_door() {
    let (server, dial, _stand_in) = under_test();
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let node = Node {
        secret: Arc::new(Secret::of_pair("one-pair", TOKEN)),
        http: Arc::new(Http::new(server.clone(), dial.clone())),
        say: say("node"),
    };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, BUDGET, echo, keeper));
    let dialer = Dialer::new(Secret::of_pair("another-pair", TOKEN), Http::new(server, dial), say("client"));
    let started = Instant::now();
    let missed = tokio::time::timeout(DOOR_LIMIT * 2, dialer.link()).await.expect("an answer in time");
    let Err(why) = missed else { panic!("a link to a node of another pair") };
    assert!(why.contains("no node took the hello"), "{why}");
    assert!(started.elapsed() >= DOOR_LIMIT, "it knocked for the door's whole limit");
    serving.abort();
}

/// The short live run of Q94 through the server of `pod-services`, with
/// throwaway channels: the largest POST that passes, whether two POSTs in
/// flight keep their order, that a stream gets nothing from before it, and
/// the rate of a session. Each result is a `MEASURE` line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_short_live_run_through_the_listed_server() {
    if std::env::var("PODSSH_TEST_SMEE_LIVE").ok().as_deref() != Some("yes") {
        eprintln!("did not run: PODSSH_TEST_SMEE_LIVE is not yes");
        return;
    }
    let Some(server) = road::listed().into_iter().next() else {
        eprintln!("did not run: pod-services lists no server of the kind {}", road::SERVICE_KIND);
        return;
    };
    let dial = road::http::tls(Trust::Default, ProxyChoice::FromEnvironment);
    let http = Http::new(server.clone(), dial.clone());
    // Throwaway channels: a fresh pair's name for each run.
    let fresh = format!("live-{}", std::process::id());
    let channel = Secret::of_pair(&fresh, TOKEN).door();
    // A reader of the channel, as each POST of the road has one.
    let _reader = link::open_stream(&http, &channel).await.expect("smee's ready");
    for size in [64 << 10, 256 << 10, 512 << 10, 700 << 10, 1 << 20] {
        let posted = http.post(&channel, &frame::frame(0, &vec![7; size * 3 / 4]), Duration::from_secs(30)).await;
        eprintln!("MEASURE a POST of about {} KiB of JSON: {posted:?}", size >> 10);
    }
    // Two POSTs in flight, each on its own connection, the second sent 5 ms
    // after the first and before its answer, twenty times, on a channel of
    // their own.
    let channel = Secret::of_pair(&format!("{fresh}-order"), TOKEN).door();
    let mut events = link::open_stream(&http, &channel).await.expect("smee's ready");
    let (a, b) = (Http::new(server.clone(), dial.clone()), Http::new(server.clone(), dial.clone()));
    let mut swapped = 0;
    for round in 0..20u64 {
        let (first, second) = (frame::frame(2 * round, b"a"), frame::frame(2 * round + 1, b"b"));
        let later = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            b.post(&channel, &second, LIMIT).await
        };
        let _ = tokio::join!(a.post(&channel, &first, LIMIT), later);
        let mut got = Vec::new();
        while got.len() < 2 {
            let Ok(Some(event)) = events.next(Duration::from_secs(30)).await else { break };
            if let Ok(frame::Message::Frame(n, _)) = frame::read(&event.data) {
                got.push(n);
            }
        }
        swapped += usize::from(got.first() != Some(&(2 * round)));
    }
    eprintln!("MEASURE the second of two POSTs in flight came first {swapped} times of 20");
    let took = one_mib_each_way(server.clone(), dial, &format!("{fresh}-session")).await;
    eprintln!("MEASURE {server}: 1 MiB each way in {} ms", took.as_millis());
}
