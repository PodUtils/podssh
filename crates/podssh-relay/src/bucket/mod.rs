//! A bucket of the S3 API as a carrier between two podssh ends (T-725), for
//! a host whose one way out is an object store. Each end writes its way's
//! objects under one prefix and reads the other's under another, so a key
//! with a write right on one prefix and a read right on the other is
//! enough; the two rights may be two key pairs, and a public-read prefix
//! needs no read key.
//!
//! It is the file-host carrier's shape ([`crate::filehost`]) with the
//! bucket as its board ([`board::BucketBoard`]): each write of a link one
//! sealed object (AES-256-GCM under the pair's key, its name a MAC of that
//! key), polled for by name, read, and deleted where the reader may; a
//! client's hello at the node's door opens a link ([`dial`], [`accept`]).
//! The pair's key here comes from a secret that both ends hold in a file
//! ([`Keys::of_bucket`]), as no relay and no pair stand behind the road.
//! The end-to-end channel runs above it, as on each road.
//!
//! Rule 2: each request goes on the road's one connection, through
//! `HTTPS_PROXY`, one at a time ([`s3::Bucket`], and the carrier's gate);
//! no listener. The endpoint is the user's: podssh names no provider.
//!
//! The road is slow: a poll of a name each 2 to 3 s while a link waits,
//! each request a billed one at most providers.

pub mod board;
pub mod s3;

#[cfg(test)]
mod standin;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
// pod-link's key pair, endpoint and style, for the callers of this road.
pub use pod_link::s3::sign::Credentials;
pub use pod_link::s3::{Endpoint, Style};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::filehost::link::{self, Link};
use crate::filehost::pace::Gate;
use crate::filehost::{Carrier, Keys, Say};
use crate::piping::dial::{BoxIo, Dial, Proto, CONNECT_LIMIT};
use crate::piping::Server;
use board::BucketBoard;

/// The least bytes of the shared secret: 128 bits.
pub const SECRET_LEAST: usize = 16;
const KEY_LABEL: &[u8] = b"podssh bucket v1 key";

/// Which end this is: the client writes the up prefix and reads the down
/// one; the node the other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Node,
}

/// Where the two ways live: the same at both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub endpoint: Endpoint,
    pub style: Style,
    pub region: String,
    pub bucket: String,
    /// The client's way to the node.
    pub up: String,
    /// The node's way to the client.
    pub down: String,
}

impl Place {
    /// A refusal of a place that two ends could not share: the two ways
    /// in one prefix, or one inside the other, would read their own notes.
    pub fn check(&self) -> Result<(), String> {
        let (up, down) = (self.up.trim_matches('/'), self.down.trim_matches('/'));
        let inside = |a: &str, b: &str| a == b || b.starts_with(&format!("{a}/")) || a.is_empty();
        if inside(up, down) || inside(down, up) {
            return Err("up and down must be two prefixes, neither empty nor inside the other".into());
        }
        if self.region.is_empty() || self.bucket.is_empty() {
            return Err("a bucket and a region are needed".into());
        }
        Ok(())
    }
}

/// The keys of an end: its write key, and its read key (none: unsigned).
#[derive(Clone)]
pub struct KeyPairs {
    pub write: Credentials,
    pub read: Option<Credentials>,
}

impl std::fmt::Debug for KeyPairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // pod-link's own Debug shows the id alone.
        f.debug_struct("KeyPairs").field("write", &self.write).field("read", &self.read).finish()
    }
}

/// The pair's key of a bucket: an HMAC of `secret` over the place, so that
/// one secret used for two places gives two keys.
pub fn keys_of(secret: &[u8], place: &Place) -> Result<Keys, String> {
    if secret.len() < SECRET_LEAST {
        return Err(format!("a secret of {} bytes: at least {SECRET_LEAST} are needed", secret.len()));
    }
    // HMAC takes a key of each length, so this cannot fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(KEY_LABEL);
    for part in [&place.endpoint.host, &place.bucket, &place.up, &place.down] {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part.as_bytes());
    }
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());
    Ok(Keys::from_bytes(*bytes))
}

/// TLS through `proxy` for `https`, verified with `trust`; TCP through it
/// for `http`, which a stand-in on the loopback serves.
pub fn dial_of(endpoint: &Endpoint, trust: podssh_ws::Trust, proxy: podssh_ws::ProxyChoice) -> Dial {
    if endpoint.secure {
        return crate::smee::http::tls(trust, proxy);
    }
    Arc::new(move |server: &Server| -> crate::piping::dial::Dialing {
        let (server, proxy) = (server.clone(), proxy.clone());
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&server.host, server.port, &proxy, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("{}:{}: {}", server.host, server.port, podssh_ws::text::said(&e)))?;
            Ok((Box::new(tcp) as BoxIo, Proto::H1))
        })
    })
}

/// The carrier of `side` at `place`, with `keys`, the pair's `secret`, and
/// each connection by `dial`.
pub fn carrier(
    place: &Place,
    side: Side,
    keys: KeyPairs,
    secret: &[u8],
    dial: Dial,
    say: Say,
) -> Result<Arc<Carrier>, String> {
    place.check()?;
    let pair = Arc::new(keys_of(secret, place)?);
    let bucket = Arc::new(s3::Bucket::new(place.endpoint.clone(), place.style, &place.region, &place.bucket, dial));
    let (write, read) = match side {
        Side::Client => (&place.up, &place.down),
        Side::Node => (&place.down, &place.up),
    };
    let board = BucketBoard::new(bucket, write, read, keys.write, keys.read, pair.door());
    Ok(Arc::new(Carrier::new(pair, Vec::new(), Arc::new(board), Gate::default(), say)))
}

/// A client's link: its hello at the node's door, then its two ways. A
/// client may not read its own way, so it cannot see the node take the
/// hello: its link starts at once, and the node's first bytes come when
/// the node's door poll finds it, 10 s later at most.
pub async fn dial(carrier: &Arc<Carrier>) -> Result<Link, String> {
    link::dial(carrier.clone()).await
}

/// The node's next link: its door polled until a client's fresh hello is
/// there, however long that takes.
pub async fn accept(carrier: &Arc<Carrier>) -> Result<Link, String> {
    loop {
        match link::accept(carrier.clone()).await {
            Ok(link) => return Ok(link),
            Err(why) if why.starts_with("no client's hello") => continue,
            Err(why) => return Err(why),
        }
    }
}

/// The longest that a client waits for the node's first bytes: the node's
/// door poll, its probe, its TARGET's dial, its first write and this end's
/// read poll, with room for a slow endpoint behind a proxy.
pub const READY_LIMIT: Duration = Duration::from_secs(5 * 60);

/// How long the last leg of a session may take to end through a bucket:
/// its Close and the node's answer each wait for the other end's next read
/// (3 s apart at most), and each object is a request of its own.
pub const LEG_END: Duration = Duration::from_secs(40);

/// How long a client's Close may take to go out through a bucket: one PUT,
/// behind the request that the one connection may still have in flight.
pub const CLOSE_LIMIT: Duration = Duration::from_secs(20);

/// The name that [`probe`] reads: no note has it, as a note's is a MAC.
pub const PROBE_NAME: &str = "podssh-probe";

/// A read, before the road starts, of a name under this end's read prefix
/// that no note has: 404 says the read key works. A 403 `AccessDenied` is
/// a key that may read but not list (AWS answers so for a missing object),
/// or one that may not read: a line says so, and the road goes on. Each
/// other answer, a wrong key or signature among them, is the refusal.
pub async fn probe(place: &Place, side: Side, keys: &KeyPairs, dial: Dial) -> Result<Option<String>, String> {
    let bucket = s3::Bucket::new(place.endpoint.clone(), place.style, &place.region, &place.bucket, dial);
    let read = match side {
        Side::Client => &place.down,
        Side::Node => &place.up,
    };
    let key = format!("{}/{PROBE_NAME}", read.trim_end_matches('/'));
    let answer = bucket.request("GET", &key, keys.read.as_ref(), &[], 64 * 1024).await;
    bucket.close().await;
    let answer = answer?;
    let text = String::from_utf8_lossy(&answer.body);
    match answer.status {
        200 | 404 => Ok(None),
        403 if text.contains("<Code>AccessDenied</Code>") => Ok(Some(format!(
            "the read key was denied a name under {read}: it may read and not list (then all is well), or it may not \
             read, and the road waits for nothing"
        ))),
        _ => Err(s3::refused(&format!("a read under {read} of {}", bucket.shown()), &answer)),
    }
}
