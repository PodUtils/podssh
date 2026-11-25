//! `--carrier dns:FILE` (T-877): the stream of a carrier in the questions
//! and answers of DNS, for a host that reaches a recursive resolver and
//! nothing else. The road is pod-link's (PodUtils/podcrates, feature `dns`):
//! the client's bytes go up in base32 labels of names under a zone of the
//! user's own, and come down in TXT records, under a selective-repeat ARQ
//! and TLS 1.3 with each end's Ed25519 key pinned by the other. podssh keeps
//! the glue: FILE, the probe of UDP, the bound of the owner's ruling Q107
//! (at most 20 queries a second and 8 in flight), and the node's listener,
//! which the user asks for with `listen`.
//!
//! FILE holds `NAME = VALUE` lines, and a line that starts with `#` is a
//! comment, as in a bucket's (`carrier_dns_file` reads it):
//!
//! - `zone`: the zone whose names carry the stream, delegated to the node;
//! - `resolver` (the client's): `system` (the first nameserver of
//!   `/etc/resolv.conf`, the default), `IP[:PORT]`, or
//!   `https://NAME[:PORT]/PATH`, a resolver of DNS over HTTPS reached through
//!   `HTTPS_PROXY` with no UDP (`carrier_dns_https`);
//! - `listen` (the node's): `IP:PORT` of UDP, as `0.0.0.0:53`;
//! - `key-file`: the path of this end's key, its file made private where it
//!   does not exist;
//! - `peer`: the other end's key: on a client, the node's; on a node, each
//!   client's that it takes, by spaces or commas;
//! - `queries-per-second` (20 at most), `in-flight` (8 at most),
//!   `query-timeout` and `poll-max` in seconds, and `answer` in bytes.
//!
//! A relative path is read from FILE's directory. No key is on the command
//! line; a key's public half alone is in FILE.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pod_link::dns::{Dns, DnsListener};
use pod_link::CarrierErrorKind;
use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::{Identity, KeyName};
use podssh_relay::serve::reverse::carrier::Link;
use podssh_relay::session::OsEntropy;

use crate::carrier_bucket::Side;
use crate::carrier_dns_https as https;
use crate::dns_road;
use crate::exitmap::sysexits::EX_NOPERM;
use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

#[path = "carrier_dns_file.rs"]
mod spec_file;

use spec_file::config;
pub(crate) use spec_file::{read, Spec};

/// The kind's word in `--carrier`.
pub(crate) const SCHEME: &str = "dns:";
/// Each direction of the pipe between the role and the road.
const PIPE: usize = 256 * 1024;
/// How many failed handshakes a node says one by one; then each 100th.
const SAID_FAILURES: u64 = 10;

/// This end's key, read or made; a line names a key that was made, for the
/// other end's `peer`.
fn key_of(spec: &Spec, say: &podssh_relay::filehost::Say) -> Result<Identity, Refusal> {
    let key = file::load(&Place::File(spec.key_file.clone()), &mut OsEntropy)
        .map_err(|why| config(&spec.file, format!("key-file: {why}")))?;
    if key.made {
        let shown = spec.key_file.display();
        let public = key.identity.public();
        say(format!("{}: made this end's key in {shown}: give {public} to the other end's peer", spec.file));
    }
    Ok(key.identity)
}

/// The carrier of this end: podssh's TLS provider, `identity`, and FILE's
/// settings.
fn carrier(spec: &Spec, identity: Identity) -> Dns {
    let mut dns = Dns::new(podssh_ws::tls::context().provider().clone(), Arc::new(identity));
    dns.dns = spec.settings;
    // A node drops a session that sends nothing for this long before its
    // handshake ends; a dialer idle at its own poll-max must not be dropped.
    dns.handshake_quiet = dns.handshake_quiet.max(spec.settings.poll_max + Duration::from_secs(1));
    dns
}

/// Where the road's lines go: stderr, as each line of the carrier.
fn say() -> podssh_relay::filehost::Say {
    Arc::new(|line: String| {
        podssh_ssh::err_line!("podssh: the DNS carrier: {line}");
    })
}

/// The one peer of a client: the node's key, which it pins; after a check
/// that FILE holds no setting of the node's.
fn client_peer(spec: &Spec) -> Result<KeyName, Refusal> {
    spec_file::for_side(spec, Side::Client)?;
    match spec.peers.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(config(&spec.file, "peer: one key on a client's side, the node's, which it pins")),
    }
}

/// The client's checks before any datagram: one peer, the resolver, and the
/// probe of UDP toward it (Q107). A host that refuses UDP is 69, with
/// nothing sent.
fn client_ready(spec: &Spec) -> Result<(SocketAddr, KeyName), Refusal> {
    let peer = client_peer(spec)?;
    let (server, _) = spec.resolver.resolve("resolver").map_err(|why| config(&spec.file, why))?;
    let unavailable = Fault::RelayUnreachable.code();
    dns_road::udp_out(server)
        .map_err(|why| Refusal { message: format!("the carrier dns:{}: {why}", spec.file), code: unavailable })?;
    Ok((server, peer))
}

/// The stream of `side`, in a tokio runtime: a pipe at once, whose far end
/// a task carries over the road once its link opens; the role's Pings wait
/// in it meanwhile. A road that fails says why and ends the pipe, which ends
/// the stream for the role (69). The checks that need no datagram come
/// first, as refusals.
pub(crate) fn open(spec: Arc<Spec>, side: Side) -> Result<Link, Refusal> {
    let say = say();
    let (ours, mut far) = tokio::io::duplex(PIPE);
    match side {
        Side::Client if spec.https.is_some() => {
            // Over DNS over HTTPS: no UDP, so no probe of it.
            let peer = client_peer(&spec)?;
            let identity = key_of(&spec, &say)?;
            let dns = carrier(&spec, identity);
            tokio::spawn(async move {
                let Some(url) = spec.https.as_ref() else { return };
                let dns = match https::carrier(dns, url).await {
                    Ok(dns) => dns,
                    Err(why) => return say(format!("{}: {why}", spec.file)),
                };
                match dns.connect(&spec.zone, &peer).await {
                    Ok((link, _)) => carry_until_settled(far, link).await,
                    Err(e) => say(format!("{}: {}", spec.file, podssh_ws::text::said(&e))),
                }
            });
        }
        Side::Client => {
            let (server, peer) = client_ready(&spec)?;
            let identity = key_of(&spec, &say)?;
            let dns = carrier(&spec, identity).to(server);
            tokio::spawn(async move {
                match dns.connect(&spec.zone, &peer).await {
                    Ok((link, _)) => carry_until_settled(far, link).await,
                    Err(e) => say(format!("{}: {}", spec.file, podssh_ws::text::said(&e))),
                }
            });
        }
        Side::Node => {
            tokio::spawn(async move {
                let link = match bind(&spec).await {
                    Ok(bound) => accept(&spec, bound).await,
                    Err(refusal) => Err(refusal),
                };
                match link {
                    Ok(mut link) => {
                        let _ = tokio::io::copy_bidirectional(&mut far, &mut link).await;
                    }
                    Err(refusal) => say(refusal.message),
                }
            });
        }
    }
    Ok(Box::new(ours))
}

/// The client's end, once its role asked [`settled`]: the task of the road
/// takes it, and answers when the link is shut. One client a process.
static CLIENT_END: std::sync::Mutex<Option<End>> = std::sync::Mutex::new(None);

struct End {
    /// Asks the task to move what the pipe still holds, then shut the link.
    finish: Arc<tokio::sync::Notify>,
    /// Ends when the link is shut, or the task ended otherwise.
    done: tokio::sync::oneshot::Receiver<()>,
}

/// How long the pipe must be empty, once the role ended, before its last
/// bytes are taken as gone into the link.
const QUIET: Duration = Duration::from_millis(200);

/// The client's two directions, as `copy_bidirectional` carries them, and an
/// end that [`settled`] asks: the role's Close is in the pipe or in the
/// link's queue when the role ends, and a process that exited then would
/// lose it (the node would wait 30 s for a ping, then exit 69).
async fn carry_until_settled(far: tokio::io::DuplexStream, link: pod_link::BoxIo) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let finish = Arc::new(tokio::sync::Notify::new());
    let (done_tx, done) = tokio::sync::oneshot::channel();
    *CLIENT_END.lock().unwrap_or_else(|e| e.into_inner()) = Some(End { finish: finish.clone(), done });
    let (mut far_r, mut far_w) = tokio::io::split(far);
    let (mut link_r, mut link_w) = tokio::io::split(link);
    let up = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                biased;
                read = far_r.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if link_w.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                },
                () = finish.notified() => {
                    // What the role wrote last, until the pipe is quiet.
                    while let Ok(Ok(n)) = tokio::time::timeout(QUIET, far_r.read(&mut buf)).await {
                        if n == 0 || link_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    break;
                }
            }
        }
        // TLS's close_notify, then the ARQ's FIN; it returns once they went.
        let _ = link_w.shutdown().await;
        let _ = done_tx.send(());
    };
    let down = async move {
        let _ = tokio::io::copy(&mut link_r, &mut far_w).await;
        let _ = far_w.shutdown().await;
    };
    tokio::join!(up, down);
}

/// Until the client's link carried the role's last bytes and was shut,
/// within `limit`. Nothing for a process with no DNS road.
pub(crate) async fn settled(limit: Duration) {
    let end = CLIENT_END.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(End { finish, done }) = end {
        finish.notify_one();
        let _ = tokio::time::timeout(limit, done).await;
    }
}

/// The node's listener, bound, with this end's key read: what [`accept`]
/// waits on. A node says that it serves only once it holds one.
pub(crate) struct Bound {
    listener: DnsListener,
}

/// The code of a failed bind of `listen`, as `pipe`'s listeners map theirs:
/// a bind that the host refuses (a port under 1024 for a user, a policy)
/// is 77; an address in use, or not of this host, is out of reach (69).
fn bind_code(kind: CarrierErrorKind) -> i32 {
    match kind {
        CarrierErrorKind::Refused | CarrierErrorKind::Io(std::io::ErrorKind::PermissionDenied) => EX_NOPERM,
        _ => Fault::RelayUnreachable.code(),
    }
}

/// The node's listener at `listen`, which the user asked for: no setting of
/// the client's in FILE, `PODSSH_LISTEN` (78), this end's key (78), then
/// the bind, which is the probe (77 or 69 where it fails).
pub(crate) async fn bind(spec: &Spec) -> Result<Bound, Refusal> {
    let say = say();
    spec_file::for_side(spec, Side::Node)?;
    let listen =
        spec.listen.ok_or_else(|| config(&spec.file, "no listen: the node's IP:PORT of UDP, as 0.0.0.0:53"))?;
    crate::pipe::listen::allowed()?;
    let identity = key_of(spec, &say)?;
    let me = identity.public();
    let clients = pod_tls::peer::Keys::new(spec.peers.clone());
    let dns = carrier(spec, identity).zone(spec.zone.clone()).with_clients(clients);
    let listener = dns.bind(listen).await.map_err(|e| {
        let refused = bind_code(e.kind) == EX_NOPERM;
        let why = if refused { "; this host refuses the listener" } else { "" };
        Refusal {
            message: format!(
                "the carrier dns:{}: cannot listen on {listen} (UDP): {}{why}",
                spec.file,
                podssh_ws::text::said(&e)
            ),
            code: bind_code(e.kind),
        }
    })?;
    say(format!("{}: answers for {} at {} (UDP), as the key {me}", spec.file, spec.zone, listener.local_addr()));
    Ok(Bound { listener })
}

/// The node's stream, once a client whose key is a `peer` of FILE finished
/// its handshake on the listener of [`bind`]. A handshake that fails leaves
/// the listener open for the next.
pub(crate) async fn accept(spec: &Spec, bound: Bound) -> Result<Link, Refusal> {
    let say = say();
    let Bound { mut listener } = bound;
    let unavailable = Fault::RelayUnreachable.code();
    let mut failed: u64 = 0;
    loop {
        match listener.accept_key().await {
            Ok((io, key)) => {
                say(format!("{}: the client of the key {key} took the stream", spec.file));
                return Ok(Box::new(io));
            }
            // The listener's own task ended: no client can come.
            Err(e) if e.kind == CarrierErrorKind::Io(std::io::ErrorKind::BrokenPipe) => {
                return Err(Refusal {
                    message: format!("the carrier dns:{}: {}", spec.file, podssh_ws::text::said(&e)),
                    code: unavailable,
                });
            }
            // One peer's handshake: a stranger's name costs a line, not the
            // node; a flood of them is said each 100th.
            Err(e) => {
                failed += 1;
                if failed <= SAID_FAILURES || failed.is_multiple_of(100) {
                    say(format!("{}: a handshake failed ({failed} so far): {}", spec.file, podssh_ws::text::said(&e)));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "carrier_dns_tests.rs"]
mod tests;
