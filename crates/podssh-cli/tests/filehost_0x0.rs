//! Interop tests of the file hosts' road (T-738) against 0x0.st's own server
//! (`mia/0x0`, software that podssh did not write), started locally by
//! `scripts/interop-filehost-0x0.sh`:
//!
//! 1. Direct `HttpHost` against `mia/0x0` using `pod-services`' exact
//!    `null-pointer-0x0` form through a local CONNECT proxy and TLS front:
//!    upload returns an `https://` secret URL and `X-Token`, download returns
//!    identical bytes, delete removes the file on disk and makes a second
//!    download fail with 404.
//! 2. Full `Carrier` + `link::dial`/`link::accept` over a stand-in meeting
//!    point (Eclipse Mosquitto when `PODSSH_MOSQUITTO_TEST_BIN` is set, else
//!    an in-memory board): a node and a client move 256 KiB each way with
//!    equal SHA-256 digests, a first host answering 429 fails over to `mia/0x0`,
//!    and every uploaded piece is deleted from `mia/0x0` once read.
//! 3. Stored-bytes check against `mia/0x0`'s real storage directory
//!    (`PODSSH_0X0_STORAGE_DIR`): before the piece is read and deleted, the
//!    bytes on disk hold no plaintext marker (planted: uploading unsealed
//!    makes this test fail with `plaintext found in mia/0x0 storage`).
//!
//! Without `PODSSH_0X0_TEST_PORT`, each test prints `did not run` and exits 0.

#![cfg(feature = "filehost")]

mod cleanup;
mod filehost_stand_in;
#[path = "update_support/mod.rs"]
mod update_support;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use filehost_stand_in::{Mosquitto, Proxy};
use podssh_relay::filehost::board::Posting;
use podssh_relay::filehost::host::Doing;
use podssh_relay::filehost::http::HttpHost;
use podssh_relay::filehost::mqtt::MqttBoard;
use podssh_relay::filehost::pace::Gate;
use podssh_relay::filehost::{link, services, Board, Carrier, Host, Keys, LinkId, Refusal, Say, Stored, Way};
use podssh_relay::session::{Entropy, OsEntropy};
use podssh_ws::url::WsUrl;
use podssh_ws::{HttpProxy, ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OX0_ID: &str = "null-pointer-0x0";
const SIZE: usize = 256 * 1024;
const PIECE: usize = 32 * 1024;
const MARKER: &[u8] = b"PODSSH-T738-PLAINTEXT-MARKER-NEVER-IN-0X0-STORAGE-0123456789ABCD";

fn ox0_port() -> Option<u16> {
    let raw = match std::env::var("PODSSH_0X0_TEST_PORT") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            println!(
                "did not run: PODSSH_0X0_TEST_PORT names no mia/0x0 server (scripts/interop-filehost-0x0.sh sets it)"
            );
            return None;
        }
    };
    Some(raw.trim().parse().expect("PODSSH_0X0_TEST_PORT must be a TCP port"))
}

fn storage_dir() -> Option<PathBuf> {
    std::env::var_os("PODSSH_0X0_STORAGE_DIR").filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-filehost-0x0-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn regular_files(dir: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(dir)
        .expect("read PODSSH_0X0_STORAGE_DIR")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect()
}

/// Unique payload of `len` bytes: a random 16-byte prefix so `mia/0x0` never
/// deduplicates across runs and always issues `X-Token`, followed by a
/// deterministic xorshift stream.
fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Entropy::fill(&mut OsEntropy, &mut out[..16]).expect("random prefix");
    let mut x = seed;
    for byte in &mut out[16..] {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *byte = x as u8;
    }
    out
}

/// An in-memory meeting point for runs without Mosquitto, and for inspecting
/// notes directly before they are cleared.
#[derive(Default)]
struct MemoryBoard(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryBoard {
    fn snapshot(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().values().cloned().collect()
    }
}

impl Board for MemoryBoard {
    fn name(&self) -> &str {
        "memory"
    }
    fn most(&self) -> usize {
        64_000
    }
    fn put<'a>(&'a self, topic: &'a str, payload: Vec<u8>) -> Posting<'a, ()> {
        self.0.lock().unwrap().insert(topic.to_string(), payload);
        Box::pin(async { Ok(()) })
    }
    fn take<'a>(&'a self, topic: &'a str) -> Posting<'a, Option<Vec<u8>>> {
        let found = self.0.lock().unwrap().get(topic).cloned();
        Box::pin(async move { Ok(found) })
    }
    fn clear<'a>(&'a self, topic: &'a str) -> Posting<'a, ()> {
        self.0.lock().unwrap().remove(topic);
        Box::pin(async { Ok(()) })
    }
}

/// A first host that always answers 429 so the carrier must fail over to the
/// next host (`mia/0x0`).
struct BusyHost {
    hits: AtomicUsize,
}

impl BusyHost {
    fn new() -> BusyHost {
        BusyHost { hits: AtomicUsize::new(0) }
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Host for BusyHost {
    fn name(&self) -> &str {
        "busy.stand-in.test"
    }
    fn most(&self) -> usize {
        8 << 20
    }
    fn per_hour(&self) -> Option<u32> {
        Some(100_000)
    }
    fn one_person(&self) -> bool {
        false
    }
    fn owns(&self, url: &str) -> bool {
        url.starts_with("https://busy.stand-in.test/")
    }
    fn upload(&self, _sealed: Vec<u8>) -> Doing<'_, Stored> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(Refusal::Busy(Some(Duration::from_secs(3600)))) })
    }
    fn fetch<'a>(&'a self, _url: &'a str, _most: usize) -> Doing<'a, Vec<u8>> {
        Box::pin(async { Err(Refusal::Failed("busy host stores nothing".into())) })
    }
    fn delete<'a>(&'a self, _stored: &'a Stored) -> Doing<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Real `mia/0x0` reached through the catalog's exact `null-pointer-0x0` form,
/// a local TLS front and a local CONNECT proxy.
struct Ox0Front {
    host: Arc<HttpHost>,
    proxy: Proxy,
    ca: PathBuf,
    acceptor: tokio_rustls::TlsAcceptor,
    dir: PathBuf,
}

impl Ox0Front {
    async fn start(tag: &str, ox0_port: u16) -> Ox0Front {
        let dir = scratch(tag);
        let (forms, missed) = services::forms(&[OX0_ID]);
        assert!(missed.is_empty() && forms.len() == 1, "catalog form for {OX0_ID}: {missed:?}");
        let form = forms.into_iter().next().unwrap();
        let upload_host = podssh_relay::filehost::http::place(&form.upload).expect("https upload").0.host;
        let mut names = vec!["127.0.0.1".to_string(), upload_host];
        names.extend(form.serves.iter().cloned());
        names.sort();
        names.dedup();
        let named: Vec<&str> = names.iter().map(String::as_str).collect();
        let (acceptor, ca) = update_support::acceptor(&dir, &named);
        let front = filehost_stand_in::front(acceptor.clone(), ox0_port).await;
        let mut routes = HashMap::new();
        for name in names.iter().filter(|n| *n != "127.0.0.1") {
            routes.insert(name.clone(), front);
        }
        let proxy = Proxy::start(routes).await;
        let via = HttpProxy::parse(&proxy.url()).expect("proxy url");
        let dial = podssh_relay::smee::http::tls(Trust::File(ca.clone()), ProxyChoice::Via(via));
        let host = Arc::new(HttpHost::new(form, dial).expect("HttpHost"));
        Ox0Front { host, proxy, ca, acceptor, dir }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_fetch_and_delete_against_mia_0x0() {
    let Some(port) = ox0_port() else { return };
    let front = Ox0Front::start("http", port).await;
    let data = payload(PIECE, 0x1234_5678);
    let digest = hex_lower(&Sha256::digest(&data));

    let stored = tokio::time::timeout(Duration::from_secs(60), front.host.upload(data.clone()))
        .await
        .expect("upload within 60 s")
        .expect("mia/0x0 upload succeeded");
    assert!(stored.url.starts_with("https://"), "expected https URL, got {}", stored.url);
    assert!(stored.url.contains("/s/"), "expected secret URL (/s/...), got {}", stored.url);
    assert!(stored.token.is_some(), "expected X-Token header from mia/0x0");
    if let Some(dir) = storage_dir() {
        let on_disk = dir.join(&digest);
        assert!(on_disk.is_file(), "mia/0x0 should store upload at {}", on_disk.display());
        assert_eq!(std::fs::metadata(&on_disk).unwrap().len(), PIECE as u64);
    }

    let back = tokio::time::timeout(Duration::from_secs(60), front.host.fetch(&stored.url, PIECE * 2))
        .await
        .expect("fetch within 60 s")
        .expect("mia/0x0 fetch succeeded");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&data), "downloaded bytes must match upload");

    tokio::time::timeout(Duration::from_secs(60), front.host.delete(&stored))
        .await
        .expect("delete within 60 s")
        .expect("mia/0x0 delete succeeded");
    if let Some(dir) = storage_dir() {
        assert!(!dir.join(&digest).exists(), "deleted piece must be removed from mia/0x0 storage");
    }

    let after = tokio::time::timeout(Duration::from_secs(60), front.host.fetch(&stored.url, PIECE * 2))
        .await
        .expect("second fetch within 60 s");
    match after {
        Err(Refusal::Failed(why)) if why.contains("404") => {}
        other => panic!("expected 404 after delete on mia/0x0, got {other:?}"),
    }
}

struct Boards {
    _mosquitto: Option<Mosquitto>,
    client: Arc<dyn Board>,
    node: Arc<dyn Board>,
}

async fn meeting_point(front: &Ox0Front) -> Boards {
    let have_mosquitto = std::env::var_os("PODSSH_MOSQUITTO_TEST_BIN").is_some_and(|v| !v.is_empty());
    if have_mosquitto {
        if let Some(broker) = Mosquitto::start(&front.dir) {
            let broker_front = filehost_stand_in::front(front.acceptor.clone(), broker.port).await;
            let url = WsUrl::parse(&format!("wss://127.0.0.1:{broker_front}/")).unwrap();
            let make = || -> Arc<dyn Board> {
                let say: podssh_relay::code::Say = Arc::new(|_| {});
                let cfg = podssh_relay::code::config(&Trust::File(front.ca.clone()), &ProxyChoice::Direct, say);
                Arc::new(MqttBoard::new(podssh_relay::code::mqtt::Point { url: url.clone(), login: None }, cfg))
            };
            println!("board: Eclipse Mosquitto over TLS");
            return Boards { _mosquitto: Some(broker), client: make(), node: make() };
        }
    }
    let mem: Arc<dyn Board> = Arc::new(MemoryBoard::default());
    println!("board: in-memory stand-in (set PODSSH_MOSQUITTO_TEST_BIN for Mosquitto)");
    Boards { _mosquitto: None, client: mem.clone(), node: mem }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carrier_moves_256_kib_each_way_with_429_failover_and_deletes_pieces() {
    let Some(port) = ox0_port() else { return };
    let front = Ox0Front::start("carrier", port).await;
    let before = storage_dir().map(|d| regular_files(&d));
    let boards = meeting_point(&front).await;

    let busy_c = Arc::new(BusyHost::new());
    let busy_n = Arc::new(BusyHost::new());
    let mut secret = [0u8; 32];
    Entropy::fill(&mut OsEntropy, &mut secret).unwrap();
    let keys = Arc::new(Keys::from_bytes(secret));
    let say: Say = Arc::new(|line| println!("  {line}"));
    let client = Arc::new(Carrier::new(
        keys.clone(),
        vec![busy_c.clone() as Arc<dyn Host>, front.host.clone() as Arc<dyn Host>],
        boards.client,
        Gate::default(),
        say.clone(),
    ));
    let node = Arc::new(Carrier::new(
        keys,
        vec![busy_n.clone() as Arc<dyn Host>, front.host.clone() as Arc<dyn Host>],
        boards.node,
        Gate::default(),
        say,
    ));

    let accepting = tokio::spawn(link::accept(node));
    let mut at_client = tokio::time::timeout(Duration::from_secs(60), link::dial(client))
        .await
        .expect("dial within 60 s")
        .expect("dial ok");
    let mut at_node = tokio::time::timeout(Duration::from_secs(60), accepting)
        .await
        .expect("accept within 60 s")
        .expect("accept task")
        .expect("accept ok");

    let up = payload(SIZE, 0x9e37_79b9);
    let down = payload(SIZE, 0x7f4a_7c15);
    let moving = async {
        tokio::join!(
            async {
                at_client.write_all(&up).await.unwrap();
                at_client.shutdown().await.unwrap();
                let mut got = Vec::new();
                at_client.read_to_end(&mut got).await.unwrap();
                got
            },
            async {
                at_node.write_all(&down).await.unwrap();
                at_node.shutdown().await.unwrap();
                let mut got = Vec::new();
                at_node.read_to_end(&mut got).await.unwrap();
                got
            }
        )
    };
    let (at_c, at_n) = tokio::time::timeout(Duration::from_secs(180), moving).await.expect("256 KiB each way in 180 s");

    assert_eq!(at_n.len(), SIZE, "node received 256 KiB");
    assert_eq!(at_c.len(), SIZE, "client received 256 KiB");
    assert_eq!(Sha256::digest(&at_n), Sha256::digest(&up), "upward SHA-256 must match");
    assert_eq!(Sha256::digest(&at_c), Sha256::digest(&down), "downward SHA-256 must match");
    assert!(busy_c.hits() >= 1 && busy_n.hits() >= 1, "each end must hit the 429 host and fail over to mia/0x0");
    let asked = front.proxy.asked.lock().unwrap().len();
    assert!(asked >= 6, "expected upload+fetch+delete each way against mia/0x0, saw {asked} CONNECTs");
    if let (Some(dir), Some(before)) = (storage_dir(), before) {
        let leaked: Vec<PathBuf> = regular_files(&dir).difference(&before).cloned().collect();
        assert!(leaked.is_empty(), "every piece read from mia/0x0 must be deleted; leaked: {leaked:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_bytes_in_mia_0x0_hold_no_plaintext() {
    let Some(port) = ox0_port() else { return };
    let front = Ox0Front::start("sealed", port).await;
    let dir = storage_dir().expect("PODSSH_0X0_STORAGE_DIR must be set to inspect mia/0x0 stored bytes");
    let before = regular_files(&dir);

    let board = Arc::new(MemoryBoard::default());
    let mut secret = [0u8; 32];
    Entropy::fill(&mut OsEntropy, &mut secret).unwrap();
    let keys = Arc::new(Keys::from_bytes(secret));
    let say: Say = Arc::new(|_| {});
    let carrier = Carrier::new(
        keys,
        vec![front.host.clone() as Arc<dyn Host>],
        board.clone() as Arc<dyn Board>,
        Gate::default(),
        say,
    );
    let link = LinkId::random(&mut OsEntropy).unwrap();

    let mut piece = payload(PIECE, 0x55aa_1337);
    piece[16..16 + MARKER.len()].copy_from_slice(MARKER);

    tokio::time::timeout(Duration::from_secs(60), carrier.send(Way::Up, &link, 0, &piece))
        .await
        .expect("send within 60 s")
        .expect("carrier send ok");

    // Inspect the actual bytes mia/0x0 wrote to disk before receive deletes them.
    let after = regular_files(&dir);
    let added: Vec<PathBuf> = after.difference(&before).cloned().collect();
    assert!(!added.is_empty(), "expected mia/0x0 to store the uploaded piece in {}", dir.display());
    for path in &added {
        let bytes = std::fs::read(path).expect("read stored file");
        assert!(
            !bytes.windows(MARKER.len()).any(|w| w == MARKER),
            "plaintext found in mia/0x0 storage: {}",
            path.display()
        );
    }
    for note in board.snapshot() {
        assert!(!note.windows(MARKER.len()).any(|w| w == MARKER), "plaintext found on board");
    }

    let opened =
        tokio::time::timeout(Duration::from_secs(60), carrier.receive(Way::Up, &link, 0, Duration::from_secs(30)))
            .await
            .expect("receive within 60 s")
            .expect("carrier receive ok");
    assert_eq!(opened, piece, "opened piece must match sent bytes");
    for path in &added {
        assert!(!path.exists(), "deleted piece {} must be gone after receive", path.display());
    }
}
