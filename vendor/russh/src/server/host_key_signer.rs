//! `Config::host_key_signer`: the server's own signer of the exchange hash,
//! asked first for each key, whose signature is the one that the client
//! checks; `None` leaves the key to russh, and an error ends the key
//! exchange. podssh's patch (vendor/patches/russh/, T-856).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // as in the test suite

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ssh_key::{Algorithm, HashAlg, PrivateKey};

use crate::cert::PublicKeyOrCertificate;
use crate::helpers::sign_with_hash_alg;
use crate::keys::PrivateKeyWithHashAlg;
use crate::{client, server};

/// What the test's signer answers.
enum Answer {
    /// Signs with the key it was given.
    Own,
    /// Leaves the key to russh.
    Russh,
    /// Refuses to sign.
    Refuse,
    /// Signs with another key: the client must refuse the signature.
    Other(PrivateKey),
}

struct Signer {
    calls: AtomicUsize,
    answer: Answer,
}

impl server::HostKeySigner for Signer {
    fn sign(
        &self,
        key: &PrivateKey,
        hash: Option<HashAlg>,
        data: &[u8],
    ) -> Option<Result<Vec<u8>, ssh_key::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let with = |key: &PrivateKey| {
            sign_with_hash_alg(&PrivateKeyWithHashAlg::new(Arc::new(key.clone()), hash), data)
        };
        match &self.answer {
            Answer::Own => Some(with(key)),
            Answer::Russh => None,
            Answer::Refuse => Some(Err(ssh_key::Error::Crypto)),
            Answer::Other(other) => Some(with(other)),
        }
    }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = crate::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct NoLogin;

impl server::Handler for NoLogin {
    type Error = crate::Error;
}

fn ed25519() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

/// One key exchange with a server whose signer answers `answer`: whether
/// the client took it, and how many times the signer was asked.
async fn handshake(answer: Answer) -> (bool, usize) {
    let signer = Arc::new(Signer { calls: AtomicUsize::new(0), answer });
    let mut config = server::Config::default();
    config.inactivity_timeout = None;
    config.keys.push(ed25519());
    config.host_key_signer = Some(signer.clone());
    let (near, far) = tokio::io::duplex(1 << 16);
    let served = tokio::spawn(async move {
        match server::run_stream(Arc::new(config), far, NoLogin).await {
            Ok(running) => running.await,
            Err(e) => Err(e),
        }
    });
    let client = client::connect_stream(Arc::new(client::Config::default()), near, Trusting);
    let took = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("a key exchange within 10 s")
        .is_ok();
    served.abort();
    (took, signer.calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn the_servers_signer_signs_each_exchange_in_the_place_of_russh() {
    let rows = [
        ("its own signature", Answer::Own, true),
        ("none, which leaves the key to russh", Answer::Russh, true),
        ("a refusal, which ends the exchange", Answer::Refuse, false),
        ("another key's signature, which the client refuses", Answer::Other(ed25519()), false),
    ];
    for (what, answer, taken) in rows {
        let (took, calls) = handshake(answer).await;
        assert_eq!(took, taken, "the signer answered {what}");
        assert_eq!(calls, 1, "the signer answered {what}: asked once");
    }
}
