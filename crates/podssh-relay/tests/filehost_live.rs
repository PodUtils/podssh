//! The live run of the file hosts' road (T-738's Prove, Q78 and Q91: short):
//! one piece of 32 KiB through each file host of `pod-services` (its kind
//! `file-host`), never more, from GitHub Actions by hand
//! (`.github/workflows/filehost-live.yml`); 32 KiB, as a write that fits a
//! note rides in it and reaches no host (T-773). For each host, first its
//! own steps alone, each timed and its answer said where it is not the
//! bytes sent (the host's form under test); then the piece sealed
//! and uploaded as the binary uploads it (its form, `HTTPS_PROXY`, the
//! road's User-Agent), its note on a board in memory (the public broker is
//! T-737's live run), then the note read, the piece downloaded and opened,
//! and deleted where the host deletes. Each host's result is said; the test
//! fails when one host fails, and names it.
//!
//! It runs only with `PODSSH_TEST_FILEHOST_LIVE=yes`; `PODSSH_FILEHOSTS`
//! names the hosts (ids of the catalog, by commas), else each of the kind.
//!
//!     PODSSH_TEST_FILEHOST_LIVE=yes cargo test -p podssh-relay --features filehost --test filehost_live -- --nocapture

#![cfg(feature = "filehost")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::filehost::board::Posting;
use podssh_relay::filehost::http::HttpHost;
use podssh_relay::filehost::pace::Gate;
use podssh_relay::filehost::{services, Board, Carrier, Host, Keys, LinkId, Say, Way};
use podssh_relay::session::OsEntropy;
use podssh_ws::{ProxyChoice, Trust};

/// The bound of one host's whole run: an upload, a download, a delete.
const HOST_LIMIT: Duration = Duration::from_secs(300);

/// A board in memory: the note's way to the reader is not under test here.
#[derive(Default)]
struct Memory(Mutex<HashMap<String, Vec<u8>>>);

impl Board for Memory {
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

/// The bytes of a piece: past the room of a note, so that a host takes it.
const PIECE: usize = 32 * 1024;

/// The host `id` of the catalog, as the binary reaches it.
fn host_of(id: &str) -> Result<Arc<dyn Host>, String> {
    let (forms, missed) = services::forms(&[id]);
    let form = forms.into_iter().next().ok_or_else(|| format!("{missed:?}"))?;
    let dial = podssh_relay::smee::http::tls(Trust::Default, ProxyChoice::FromEnvironment);
    Ok(Arc::new(HttpHost::new(form, dial)?))
}

/// The host's own steps, each within its bound and timed: an upload of
/// random bytes, their download, their delete. What came back that is not
/// what went is said by its length and its first bytes, so a page that a
/// host gives in a file's place is named.
async fn steps(host: &dyn Host) -> Result<(), String> {
    let mut bytes = vec![0u8; PIECE];
    podssh_relay::session::Entropy::fill(&mut OsEntropy, &mut bytes).map_err(|e| e.to_string())?;
    let step = Duration::from_secs(120);
    let at = Instant::now();
    let stored = tokio::time::timeout(step, host.upload(bytes.clone()))
        .await
        .map_err(|_| "upload: no answer within 120 s".to_string())?
        .map_err(|e| format!("upload: {e:?}"))?;
    println!("  upload: {} ms, {}", at.elapsed().as_millis(), stored.url);
    let at = Instant::now();
    let back = tokio::time::timeout(step, host.fetch(&stored.url, PIECE * 2))
        .await
        .map_err(|_| "download: no answer within 120 s".to_string())?
        .map_err(|e| format!("download: {e:?}"))?;
    println!("  download: {} ms, {} bytes", at.elapsed().as_millis(), back.len());
    if back != bytes {
        let head = String::from_utf8_lossy(&back[..back.len().min(160)]).replace(['\n', '\r'], " ");
        return Err(format!("download: {} bytes, not the {PIECE} sent; they begin: {head}", back.len()));
    }
    let at = Instant::now();
    tokio::time::timeout(step, host.delete(&stored))
        .await
        .map_err(|_| "delete: no answer within 120 s".to_string())?
        .map_err(|e| format!("delete: {e:?}"))?;
    println!("  delete: {} ms", at.elapsed().as_millis());
    Ok(())
}

/// One piece of [`PIECE`] through the host `id`, sealed by the carrier: the
/// time it took, or why not.
async fn one_piece(id: &str) -> Result<Duration, String> {
    let host = host_of(id)?;
    steps(host.as_ref()).await?;
    let say: Say = Arc::new(|line| println!("  {line}"));
    // Throwaway keys of this run alone: nobody else can open the piece.
    let mut secret = [0u8; 32];
    podssh_relay::session::Entropy::fill(&mut OsEntropy, &mut secret).map_err(|e| e.to_string())?;
    let keys = Arc::new(Keys::from_bytes(secret));
    let carrier = Carrier::new(keys, vec![host], Arc::new(Memory::default()), Gate::default(), say);
    let link = LinkId::random(&mut OsEntropy).map_err(|e| e.to_string())?;
    let mut piece = vec![0u8; PIECE];
    podssh_relay::session::Entropy::fill(&mut OsEntropy, &mut piece).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let run = async {
        carrier.send(Way::Up, &link, 0, &piece).await?;
        carrier.receive(Way::Up, &link, 0, Duration::from_secs(60)).await
    };
    let back = tokio::time::timeout(HOST_LIMIT, run).await.map_err(|_| "no end within 300 s".to_string())??;
    if back != piece {
        return Err("the piece came back changed".into());
    }
    Ok(started.elapsed())
}

#[tokio::test]
async fn one_piece_of_32_kib_goes_through_each_file_host() {
    if std::env::var("PODSSH_TEST_FILEHOST_LIVE").ok().as_deref() != Some("yes") {
        println!("did not run: PODSSH_TEST_FILEHOST_LIVE is not yes (filehost-live.yml sets it)");
        return;
    }
    let (every, _) = services::ids();
    let named = std::env::var("PODSSH_FILEHOSTS").ok().filter(|v| !v.trim().is_empty());
    let ids: Vec<String> = match named {
        Some(list) => list.split(',').map(|id| id.trim().to_string()).filter(|id| !id.is_empty()).collect(),
        None => every.iter().map(|id| id.to_string()).collect(),
    };
    assert!(!ids.is_empty(), "no host to run through");
    let mut failed = Vec::new();
    for id in &ids {
        println!("{id}:");
        match one_piece(id).await {
            Ok(took) => println!("{id}: 32 KiB up, down and opened in {} ms", took.as_millis()),
            Err(why) => {
                println!("{id}: FAILED: {why}");
                failed.push(format!("{id}: {why}"));
            }
        }
    }
    assert!(failed.is_empty(), "hosts that failed: {failed:#?}");
}
