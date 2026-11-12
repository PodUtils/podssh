//! Tor's onion services (T-578): a node reached by its onion address, with no
//! listener of its own and no account, through volunteers' relays. The node's
//! service is Arti's, in this process: its circuits to its introduction
//! points and to each client's rendezvous point are connections out to Tor
//! relays, through the same dial and proxy as the client's first hops, so the
//! node binds nothing.
//!
//! The service's identity key is kept in Arti's keystore under the client's
//! `state_dir` (`keystore/hss/NICKNAME/`), and read again at the next launch,
//! so that the address stays: a caller gives each service a `state_dir` of
//! its own. Restricted discovery, where keys are given, lets only the holders
//! of those keys decrypt the service's descriptor, so that a stranger who
//! learns the address cannot find its introduction points; tor-hsservice
//! calls it a defence against floods, not access control, which is why the
//! caller's end-to-end channel still checks each end above the stream.

use std::pin::Pin;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{HsClientDescEncKey, HsId, KeystoreSelector};
use futures::{Stream, StreamExt as _};
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsClientDescEncSecretKey};
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hsservice::{HsNickname, RunningOnionService, StreamRequest};
use tor_llcrypto::pk::curve25519;
use tor_proto::stream::IncomingStreamRequest;

use crate::client::{arti_failure, failure, Failure, Tor, TorStream};

/// A key of restricted discovery: an x25519 secret that a client holds, and
/// whose public half the service lists. A caller may make it of a secret
/// that both ends already share, so that no word passes between them.
#[derive(Clone)]
pub struct Discovery([u8; 32]);

impl Discovery {
    /// The key of these 32 bytes of secret.
    pub fn from_secret(bytes: [u8; 32]) -> Discovery {
        Discovery(bytes)
    }

    fn secret(&self) -> HsClientDescEncSecretKey {
        HsClientDescEncSecretKey::from(curve25519::StaticSecret::from(self.0))
    }

    fn public_key(&self) -> HsClientDescEncKey {
        HsClientDescEncKeypair::from_secret_key(self.secret()).public().clone()
    }

    /// The public half, as C tor and Arti write it:
    /// `descriptor:x25519:BASE32`.
    pub fn public(&self) -> String {
        self.public_key().to_string()
    }
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret is never shown.
        write!(f, "Discovery({})", self.public())
    }
}

/// What a service needs.
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    /// The name of the service in the keystore and the state: a slug,
    /// such as `podssh`.
    pub nickname: String,
    /// The virtual port that the service answers; a stream to another is
    /// refused as a C tor service refuses it.
    pub port: u16,
    /// The public halves of the keys of restricted discovery
    /// ([`Discovery::public`]); none: any client that knows the address.
    pub allowed: Vec<String>,
}

/// Whether `host` is an onion address of a v3 service: 56 letters of base32
/// and `.onion`, its checksum right.
pub fn is_onion(host: &str) -> bool {
    HsId::from_str(host).is_ok()
}

/// An onion service, launched: its address, and the streams that clients
/// open to its port. Dropping it stops the service.
pub struct Onion {
    address: String,
    port: u16,
    service: Arc<RunningOnionService>,
    streams: Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
    tor: Tor,
}

impl Tor {
    /// Launch the onion service of `options` on this client: its key read
    /// from the keystore, or made there at the first launch. It returns once
    /// the service runs, before its descriptor is published
    /// ([`Onion::published`] waits for that).
    pub fn serve_onion(&self, options: &ServiceOptions) -> Result<Onion, Failure> {
        const STEP: &str = "the onion service";
        let nickname = HsNickname::from_str(&options.nickname).map_err(|e| failure(STEP, e))?;
        let mut builder = OnionServiceConfigBuilder::default();
        builder.nickname(nickname);
        if !options.allowed.is_empty() {
            builder.restricted_discovery().enabled(true);
            for (n, text) in options.allowed.iter().enumerate() {
                let key = HsClientDescEncKey::from_str(text)
                    .map_err(|e| failure(STEP, format!("the key of restricted discovery {}: {e}", n + 1)))?;
                // A client's name in the service's list, never on the wire.
                let name = HsClientNickname::from_str(&format!("client-{}", n + 1)).map_err(|e| failure(STEP, e))?;
                builder.restricted_discovery().static_keys().access().push((name, key));
            }
        }
        let config = builder.build().map_err(|e| failure(STEP, e))?;
        let launched = self.client.launch_onion_service(config).map_err(|e| arti_failure(STEP, &e))?;
        let Some((service, requests)) = launched else {
            return Err(failure(STEP, "Arti says that the service is disabled"));
        };
        let Some(id) = service.onion_address() else {
            return Err(failure(STEP, "no identity key of the service in the keystore"));
        };
        // The address is the node's own word to its operators: not redacted.
        let address = id.display_unredacted().to_string();
        let streams = Box::pin(tor_hsservice::handle_rend_requests(requests));
        Ok(Onion { address, port: options.port, service, streams, tor: self.clone() })
    }

    /// A stream to `port` of the onion service at `address`, within `wait`.
    /// With `discovery`, its key goes to this client's keystore first, in
    /// the place of another kept for that service, so that a service of
    /// restricted discovery that lists it can be found.
    pub async fn connect_onion(
        &self,
        address: &str,
        port: u16,
        discovery: Option<&Discovery>,
        wait: Duration,
    ) -> Result<TorStream, Failure> {
        let id = HsId::from_str(address).map_err(|e| failure("the onion address", e))?;
        if let Some(key) = discovery {
            self.keep_discovery(id, key)?;
        }
        self.connect(address, port, wait).await
    }

    /// `key` in the keystore for the service `id`: kept when it is there
    /// already, else put there, after the one of an earlier pair.
    fn keep_discovery(&self, id: HsId, key: &Discovery) -> Result<(), Failure> {
        const STEP: &str = "the key of restricted discovery";
        match self.client.get_service_discovery_key(id) {
            Ok(Some(kept)) if kept == key.public_key() => return Ok(()),
            Ok(Some(_)) => {
                self.client
                    .remove_service_discovery_key(KeystoreSelector::Primary, id)
                    .map_err(|e| arti_failure(STEP, &e))?;
            }
            Ok(None) => {}
            Err(e) => return Err(arti_failure(STEP, &e)),
        }
        let inserted = self.client.insert_service_discovery_key(KeystoreSelector::Primary, id, key.secret());
        inserted.map(|_| ()).map_err(|e| arti_failure(STEP, &e))
    }
}

impl Onion {
    /// The address, `BASE32.onion`, in lower case.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Wait until the service says that it is reachable: its introduction
    /// points up and its descriptor published, within `wait`; else why not.
    pub async fn published(&self, wait: Duration) -> Result<(), Failure> {
        const STEP: &str = "the onion service's descriptor";
        let mut events = self.service.status_events();
        let mut now = self.service.status();
        let reached = async {
            loop {
                if now.state().is_fully_reachable() {
                    return true;
                }
                match events.next().await {
                    Some(status) => now = status,
                    None => return false,
                }
            }
        };
        match tokio::time::timeout(wait, reached).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(failure(STEP, "the service stopped")),
            Err(_) => {
                let status = self.service.status();
                let problem = status.current_problem().map_or_else(String::new, |p| format!(": {p:?}"));
                let state = status.state();
                Err(failure(STEP, format!("not published within {} s ({state:?}{problem})", wait.as_secs())))
            }
        }
    }

    /// The next stream to the service's port; a stream to another port, or
    /// a request that is no stream, is refused as C tor refuses it. `None`
    /// once the service ends.
    pub async fn accept(&mut self) -> Option<TorStream> {
        while let Some(request) = self.streams.next().await {
            let port = match request.request() {
                IncomingStreamRequest::Begin(begin) => Some(begin.port()),
                _ => None,
            };
            if port != Some(self.port) {
                let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
                continue;
            }
            // A client that left before its CONNECTED is no stream.
            if let Ok(stream) = request.accept(Connected::new_empty()).await {
                return Some(TorStream::served(stream, self.tor.client.clone(), self.service.clone()));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_of_discovery_shows_its_public_half_as_c_tor_writes_it() {
        let key = Discovery::from_secret([7; 32]);
        let public = key.public();
        assert!(public.starts_with("descriptor:x25519:"), "{public}");
        assert_eq!(HsClientDescEncKey::from_str(&public).unwrap(), key.public_key());
        assert_ne!(Discovery::from_secret([8; 32]).public(), public);
        assert!(!format!("{key:?}").contains("[7"), "the secret was shown");
    }

    #[test]
    fn an_onion_address_is_one_of_a_v3_service() {
        // The address of the Tor Project's own site, as it publishes it.
        assert!(is_onion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"));
        assert!(!is_onion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wia.onion"));
        assert!(!is_onion("www.torproject.org"));
        assert!(!is_onion("sub.2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"));
    }
}
