//! Tor's onion services (T-578) against a Tor network of C tor on this host,
//! software that podssh did not write: chutney's network `basic` (four
//! authorities and five exits, each an HSDir, as chutney's `TestingTorNetwork`
//! votes), whose arti-client configuration `PODSSH_TEST_TOR_NETWORK` names
//! (`scripts/tor-net.sh start`). A node's service, Arti's in this process,
//! publishes its descriptor there and takes a client's stream through a
//! rendezvous point; restricted discovery hides it from a client with no
//! key; and a second start, with the same state, keeps its address. With no
//! network the tests say so and pass, as the other tests of this crate do.
//! The live run on Tor's own network is asked for alone.

use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_tor::{Discovery, Options, ServiceOptions, Tor};
use podssh_ws::dial::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const NETWORK_ENV: &str = "PODSSH_TEST_TOR_NETWORK";
/// The service's virtual port, as podssh's node serves it.
const PORT: u16 = 22;
/// A bootstrap in the private network: a few seconds, with room.
const BOOTSTRAP: Duration = Duration::from_secs(120);
/// Three introduction points and a descriptor at each HSDir of the ring:
/// seconds on a quiet host, minutes on a busy runner, as on Tor's own
/// network, where the introduction points and the upload take minutes.
const PUBLISH: Duration = Duration::from_secs(600);
const LIVE_PUBLISH: Duration = PUBLISH;
/// The descriptor fetched, the introduction and the rendezvous.
const REACH: Duration = Duration::from_secs(120);
const MIB: usize = 1 << 20;

fn network() -> Option<String> {
    let Some(file) = std::env::var_os(NETWORK_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{NETWORK_ENV} is not set: no private Tor network, nothing to test (scripts/tor-net.sh)");
        return None;
    };
    Some(std::fs::read_to_string(&file).unwrap())
}

/// A home of the test's own, made empty.
fn home(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("podssh-tor-onion-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    home
}

/// A client of the private network whose state and cache are under `home`;
/// the relays are on this host, reached directly.
async fn tor(home: &Path, network: &str) -> Tor {
    client(home, Some(network), ProxyChoice::Direct).await
}

/// A client of `network`, else of Tor's own, through `proxy`.
async fn client(home: &Path, network: Option<&str>, proxy: ProxyChoice) -> Tor {
    let _ = podssh_ws::crypto::provider().install_default();
    let options = Options {
        state_dir: home.join("state"),
        cache_dir: home.join("cache"),
        proxy,
        // chutney's relays listen on ports from 5000 up; Tor's own network
        // is reached as the host allows.
        first_hop_ports: None,
        trust_directories: true,
        network: network.map(str::to_string),
        bridges: Vec::new(),
        trust: podssh_ws::Trust::Default,
    };
    Tor::bootstrap(&options, BOOTSTRAP).await.unwrap_or_else(|f| panic!("{f}"))
}

fn service(allowed: Vec<String>) -> ServiceOptions {
    ServiceOptions { nickname: "podssh".into(), port: PORT, allowed }
}

/// 1 MiB that no two runs of a byte repeat soon.
fn pattern() -> Vec<u8> {
    (0..MIB).map(|i| (i % 251) as u8 ^ (i >> 12) as u8).collect()
}

/// A node's service, of restricted discovery for one key, reached by the
/// client that holds it: 1 MiB each way through the rendezvous circuit. A
/// stream to another port is refused; a client with no key, or another
/// key, cannot find the service at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_s_onion_service_carries_a_mebibyte_each_way_and_hides_from_a_stranger() {
    let Some(network) = network() else { return };
    let (node_home, client_home, stranger_home) = (home("node"), home("client"), home("stranger"));
    let key = Discovery::from_secret([42; 32]);
    let node = tor(&node_home, &network).await;
    let onion = node.serve_onion(&service(vec![key.public()])).unwrap_or_else(|f| panic!("{f}"));
    let address = onion.address().to_string();
    assert!(podssh_tor::onion::is_onion(&address), "{address}");
    let began = std::time::Instant::now();
    onion.published(PUBLISH).await.unwrap_or_else(|f| panic!("{f}"));
    eprintln!("the descriptor was published in {} s", began.elapsed().as_secs());
    let stopped = echo(onion);
    let client = tor(&client_home, &network).await;
    carry(&client, &address, &key).await;

    // Another port of the same service: refused by the node, as C tor refuses it.
    let other = client.connect_onion(&address, PORT + 1, Some(&key), REACH).await;
    assert!(other.is_err(), "a stream to port {} was taken", PORT + 1);

    // A client with no key of the service, and one with another key, never
    // reach its introduction points: its descriptor's inner layer is not
    // theirs to read.
    let stranger = tor(&stranger_home, &network).await;
    let refused = stranger.connect_onion(&address, PORT, None, REACH).await;
    assert!(refused.is_err(), "a client with no key of restricted discovery reached the service");
    let other_key = Discovery::from_secret([43; 32]);
    let refused = stranger.connect_onion(&address, PORT, Some(&other_key), REACH).await;
    assert!(refused.is_err(), "a client with another key reached the service");

    stopped.abort();
    for dir in [node_home, client_home, stranger_home] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The node's side: each stream to the service echoed, as a far end of the
/// layer answers, until the task is stopped, which stops the service.
fn echo(mut onion: podssh_tor::Onion) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(stream) = onion.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    })
}

/// The client's side: a stream to the service at `address` with `key`, and
/// 1 MiB each way through it, the same bytes back.
async fn carry(client: &Tor, address: &str, key: &Discovery) {
    let stream = client.connect_onion(address, PORT, Some(key), REACH).await.unwrap_or_else(|f| panic!("{f}"));
    let (mut read, mut write) = tokio::io::split(stream);
    let sent = pattern();
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            write.write_all(&sent).await.unwrap();
            write.flush().await.unwrap();
            write
        })
    };
    let mut back = vec![0u8; MIB];
    tokio::time::timeout(REACH, read.read_exact(&mut back)).await.expect("1 MiB back within the limit").unwrap();
    let _write = writer.await.unwrap();
    assert!(back == sent, "the bytes that came back are not those sent");
}

/// The live run of the entry's Decision (Q91), asked for with
/// `PODSSH_TEST_TOR_ONION_LIVE=yes`: on Tor's own network, through
/// `HTTPS_PROXY` when one is set, a service of a throwaway key (a new state,
/// removed at the end), one bootstrap at each end, 1 MiB each way, and the
/// service stopped, so that its descriptor expires unused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_a_throwaway_service_on_tor_s_own_network_carries_a_mebibyte_each_way() {
    if std::env::var("PODSSH_TEST_TOR_ONION_LIVE").ok().as_deref() != Some("yes") {
        eprintln!("PODSSH_TEST_TOR_ONION_LIVE is not yes: no live run on Tor's own network");
        return;
    }
    let (node_home, client_home) = (home("live-node"), home("live-client"));
    let key = Discovery::from_secret(rand_secret());
    let node = client(&node_home, None, ProxyChoice::FromEnvironment).await;
    let onion = node.serve_onion(&service(vec![key.public()])).unwrap_or_else(|f| panic!("{f}"));
    let address = onion.address().to_string();
    onion.published(LIVE_PUBLISH).await.unwrap_or_else(|f| panic!("{f}"));
    let stopped = echo(onion);
    let visitor = client(&client_home, None, ProxyChoice::FromEnvironment).await;
    carry(&visitor, &address, &key).await;
    stopped.abort();
    drop(node);
    for dir in [node_home, client_home] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A key of discovery of this run alone: the clock and the process, hashed
/// by the standard library's random state, which the OS seeds.
fn rand_secret() -> [u8; 32] {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_usize(i);
        hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    out
}

/// The service's key is kept in its state: a second start with the same
/// state has the same address, and a start with another state another one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_start_keeps_the_address() {
    let Some(network) = network() else { return };
    let (kept_home, other_home) = (home("kept"), home("other"));
    let first = {
        let node = tor(&kept_home, &network).await;
        let onion = node.serve_onion(&service(Vec::new())).unwrap_or_else(|f| panic!("{f}"));
        onion.address().to_string()
    };
    // The first client's tasks let its state go as they end.
    let mut second = None;
    let mut last = String::new();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let node = tor(&kept_home, &network).await;
        match node.serve_onion(&service(Vec::new())) {
            Ok(onion) => {
                second = Some(onion.address().to_string());
                break;
            }
            Err(f) => last = f.to_string(),
        }
    }
    let second = second.unwrap_or_else(|| panic!("no second start within 30 s: {last}"));
    assert_eq!(second, first, "the second start has another address: the service's key was not kept");
    let node = tor(&other_home, &network).await;
    let other = node.serve_onion(&service(Vec::new())).unwrap_or_else(|f| panic!("{f}"));
    assert_ne!(other.address(), first, "two states made the same key");
    for dir in [kept_home, other_home] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
