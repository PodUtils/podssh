//! The gateway's login upstream (T-836, path (b) of its Decision): a fresh
//! Ed25519 key for each login, a user certificate of it signed by the
//! route's CA (`pod-relay`'s `Mint::sign_with` with the two extensions that
//! a stock sshd needs for a pty and a forward, T-903; a CA of RSA or ECDSA,
//! which `Mint` does not sign with, by podssh's `cert::certify`, as
//! `podssh keygen -s` signs), then russh's client over a TCP connection that
//! is dialed as a forward is, through `HTTPS_PROXY` where it is set. The
//! upstream's host key must be the route's pinned one; any other ends the
//! dial before a byte of the login. The whole dial has one time limit: the
//! gateway's caller holds the client's connection while it waits.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pod_identity::Identity;
use pod_relay::grant::{Extension, Mint};
use podssh_ws::dial::{self, ProxyChoice};
use russh::client;
use russh::keys::ssh_key::certificate::Certificate;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData};
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Preferred, SshId};
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::Route;
use crate::cert::Request;
use crate::keygen::{generate, KeyKind};
use crate::known_hosts::fingerprint;

/// The longest that a login upstream may take: the TCP connection (a
/// proxy's answer too), the key exchange and the certificate's login.
pub const DIAL_LIMIT: Duration = Duration::from_secs(20);

/// How long a certificate is valid after it is made: long enough for its
/// one login, short enough that a copy is worth nothing soon after.
pub const LIFE: u64 = 30;

/// How long before now a certificate is valid, for an upstream whose clock
/// is behind the gateway's, as `ssh-keygen -V +TIME` starts a minute back.
pub const SKEW: u64 = 60;

/// The longest login name that a certificate's key id holds, in bytes.
const MOST_NAME: usize = 64;

/// A logged-in upstream: its handle, and `gone`, whose sender drops when
/// the upstream's connection ends.
pub struct Upstream {
    pub handle: client::Handle<Pinned>,
    pub gone: watch::Receiver<()>,
}

/// The key id of a login's certificate, which the upstream's log names:
/// the route, the login name (printable ASCII alone, cut short) and the
/// fingerprint of the key that signed in at the gateway.
pub fn key_id(route: &Route, user: &str, who: &str) -> String {
    let mut name: String = user.chars().map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect();
    if name.len() > MOST_NAME {
        name.truncate(MOST_NAME);
        name.push_str("...");
    }
    format!("podssh-gateway route={} user={name} key={who}", route.pattern)
}

/// The certificate of `fresh` for `route` at `now` (seconds since the
/// epoch): the route's principal alone, a pty and forwards permitted and
/// nothing else (no agent, no X11, no user rc), and the route's
/// `source-address` where it gives one.
pub fn certificate(route: &Route, fresh: &PublicKey, key_id: &str, now: u64) -> Result<Certificate, String> {
    match (route.ca.key_data(), fresh.key_data()) {
        (KeypairData::Ed25519(ca), KeyData::Ed25519(key)) => minted(route, ca, key, key_id, now),
        _ => certified(route, fresh, key_id, now),
    }
}

/// The extensions of a login's certificate: a pty and forwards, and
/// nothing else (no agent, no X11, no user rc).
const PERMITS: [Extension<'static>; 2] = [Extension::PermitPty, Extension::PermitPortForwarding];

/// [`certificate`] by `pod-relay`'s `Mint`, for an Ed25519 CA.
fn minted(
    route: &Route,
    ca: &Ed25519Keypair,
    key: &Ed25519PublicKey,
    key_id: &str,
    now: u64,
) -> Result<Certificate, String> {
    let issuer = Identity::from_seed(&Zeroizing::new(ca.private.to_bytes()));
    // The data of `source-address` is a string of the list, as OpenSSH
    // writes an option with a value.
    let source = route.source_address.as_ref().map(|list| {
        let mut data = (list.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(list.as_bytes());
        data
    });
    let critical: Vec<(&str, &[u8])> = source.iter().map(|data| ("source-address", data.as_slice())).collect();
    let principals = [route.principal.clone()];
    let mint = Mint {
        nonce: rand::random(),
        key: pod_identity::PublicKey(key.0),
        serial: rand::random(),
        key_id,
        principals: &principals,
        valid_after: now.saturating_sub(SKEW),
        valid_before: now.saturating_add(LIFE),
        critical: &critical,
    };
    let cert = mint.sign_with(&issuer, &PERMITS).map_err(|e| format!("could not sign the certificate: {e}"))?;
    Certificate::from_bytes(&cert.blob()).map_err(|e| format!("the certificate does not read back: {e}"))
}

/// [`certificate`] by podssh's `cert::certify`, for a CA of RSA or ECDSA.
fn certified(route: &Route, fresh: &PublicKey, key_id: &str, now: u64) -> Result<Certificate, String> {
    let mut request = Request::new(key_id, false);
    request.principals = vec![route.principal.clone()];
    request.serial = rand::random();
    request.valid_after = now.saturating_sub(SKEW);
    request.valid_before = now.saturating_add(LIFE);
    request.option("clear")?;
    for permit in PERMITS {
        request.option(permit.name())?;
    }
    if let Some(list) = &route.source_address {
        request.option(&format!("source-address={list}"))?;
    }
    crate::cert::certify(&route.ca, fresh, &request, HashAlg::Sha512)
}

/// Log in at `route`'s upstream for the client key `who` under the login
/// name `user`, within [`DIAL_LIMIT`]. `Err` is one line for serve's log.
pub async fn log_in(route: &Route, user: &str, who: &str) -> Result<Upstream, String> {
    let at = format!("{}:{}", route.host, route.port);
    match tokio::time::timeout(DIAL_LIMIT, log_in_now(route, user, who)).await {
        Ok(Ok(upstream)) => Ok(upstream),
        Ok(Err(why)) => Err(format!("the upstream {at}: {why}")),
        Err(_) => Err(format!("the upstream {at} did not let the gateway in within {} s", DIAL_LIMIT.as_secs())),
    }
}

async fn log_in_now(route: &Route, user: &str, who: &str) -> Result<Upstream, String> {
    let fresh = generate(KeyKind::Ed25519, "podssh-gateway")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "this host's clock is before 1970")?.as_secs();
    let certificate = certificate(route, fresh.public_key(), &key_id(route, user, who), now)?;
    let tcp = dial::dial(&route.host, route.port, &ProxyChoice::FromEnvironment, DIAL_LIMIT)
        .await
        .map_err(|e| e.to_string())?;
    // Each keystroke of a session goes at once.
    let _ = tcp.set_nodelay(true);
    let (alive, gone) = watch::channel(());
    let seen = Arc::new(Mutex::new(None));
    let pinned = Pinned { pin: route.host_key.clone(), seen: seen.clone(), _alive: alive };
    let mut handle = match client::connect_stream(Arc::new(config(&route.host_key)), tcp, pinned).await {
        Ok(handle) => handle,
        Err(e) => {
            let other = seen.lock().unwrap_or_else(|p| p.into_inner()).take();
            return Err(match other {
                Some(other) => format!(
                    "its host key is {other}, not {} that the route pins: refused before the login",
                    fingerprint(&route.host_key)
                ),
                None => format!("the SSH handshake failed: {e}"),
            });
        }
    };
    let principal = route.principal.clone();
    let answer = handle
        .authenticate_openssh_cert(principal.as_str(), Arc::new(fresh), certificate)
        .await
        .map_err(|e| format!("the login failed: {e}"))?;
    if !answer.success() {
        return Err(format!(
            "it refused the certificate for {principal}: it must trust the CA {} (TrustedUserCAKeys) and take the \
             principal {principal} for that user",
            fingerprint(route.ca.public_key())
        ));
    }
    Ok(Upstream { handle, gone })
}

/// russh's configuration of the upstream's client: the pinned key's
/// algorithm alone, so that the upstream shows that key; no cut of an idle
/// session; serve's keepalive; podssh's window.
fn config(pin: &PublicKey) -> client::Config {
    let mut preferred = Preferred::default();
    let wanted = match pin.algorithm() {
        Algorithm::Rsa { .. } => {
            vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }]
        }
        other => vec![other],
    };
    preferred.key = Cow::Owned(wanted);
    client::Config {
        client_id: SshId::Standard(Cow::Owned(super::super::server_id())),
        inactivity_timeout: None,
        keepalive_interval: Some(super::super::KEEPALIVE),
        window_size: crate::run::WINDOW,
        nodelay: true,
        preferred,
        ..client::Config::default()
    }
}

/// The upstream's client: the route's pinned key, and nothing else, is
/// trusted. The key that it met instead is kept for the line.
pub struct Pinned {
    pin: PublicKey,
    seen: Arc<Mutex<Option<String>>>,
    /// Dropped with the client's session: the gateway learns that the
    /// upstream ended.
    _alive: watch::Sender<()>,
}

impl client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let shown = match offered {
            PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.pin.key_data() => return Ok(true),
            PublicKeyOrCertificate::PublicKey { key, .. } => fingerprint(key),
            PublicKeyOrCertificate::Certificate(_) => "a host certificate".to_string(),
        };
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(shown);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn route(source_address: Option<&str>) -> Route {
        route_of(KeyKind::Ed25519, source_address)
    }

    fn route_of(ca: KeyKind, source_address: Option<&str>) -> Route {
        let key = || generate(KeyKind::Ed25519, "").expect("a key");
        Route {
            pattern: "team-*".into(),
            host: "10.0.0.5".into(),
            port: 22,
            host_key: key().public_key().clone(),
            keys: vec![key().public_key().clone()],
            principal: "deploy".into(),
            ca: Arc::new(generate(ca, "").expect("a CA")),
            ca_path: PathBuf::from("/etc/podssh/ca"),
            source_address: source_address.map(str::to_string),
            line: 1,
        }
    }

    /// The certificate holds what the upstream judges: the one principal,
    /// a window of [`SKEW`] before now to [`LIFE`] after it, a pty and
    /// forwards alone, the source address where the route gives one, and
    /// the route's CA as its signer, whose signature ssh-key checks. The
    /// same for each kind of CA: Ed25519 (`pod-relay`'s `Mint`), ECDSA and
    /// RSA (`cert::certify`).
    #[test]
    fn a_certificate_holds_the_route_s_principal_window_and_permits() {
        let kinds = [KeyKind::Ed25519, KeyKind::Ecdsa(russh::keys::EcdsaCurve::NistP256), KeyKind::Rsa(2048)];
        for kind in kinds {
            let team = route_of(kind, Some("10.0.0.1"));
            let fresh = generate(KeyKind::Ed25519, "").unwrap();
            let id = key_id(&team, "team-web\u{1b}[2J", "SHA256:abc");
            assert_eq!(id, "podssh-gateway route=team-* user=team-web?[2J key=SHA256:abc", "no control byte");
            let made = certificate(&team, fresh.public_key(), &id, 1_000_000).expect("signed");
            assert_eq!(made.valid_principals(), ["deploy".to_string()]);
            assert_eq!((made.valid_after(), made.valid_before()), (1_000_000 - SKEW, 1_000_000 + LIFE));
            let extensions: Vec<&String> = made.extensions().keys().collect();
            assert_eq!(extensions, ["permit-port-forwarding", "permit-pty"], "{kind:?}");
            assert_eq!(made.critical_options().get("source-address").map(String::as_str), Some("10.0.0.1"));
            assert_eq!(made.signature_key(), team.ca.public_key().key_data());
            assert_eq!(made.public_key(), fresh.public_key().key_data());
            assert_eq!(made.key_id(), id);
            let ca = team.ca.public_key().fingerprint(HashAlg::Sha256);
            made.validate_at(1_000_000, [&ca]).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            let open = certificate(&route_of(kind, None), fresh.public_key(), &id, 1_000_000).unwrap();
            assert!(open.critical_options().is_empty(), "no source-address unless the route gives one");
        }
        let long = key_id(&route(None), &"x".repeat(200), "SHA256:abc");
        assert!(long.contains(&format!("user={}... ", "x".repeat(MOST_NAME))), "{long}");
    }
}
