//! An end's certificate on Syncthing's relays (T-571): the relay names a
//! device by the SHA-256 of its certificate, so the node's certificate is
//! made the same each time from the pair's secret, and its client knows the
//! node's device ID with no word between them. Ed25519, self-signed, with an
//! empty name and fixed dates, as the relay checks no chain; built here in
//! DER, whose bytes Ed25519's deterministic signature keeps the same. And
//! the TLS of a relay: this end's certificate, the relay held to its own
//! device ID (the pool's URL names it), ALPN `bep-relay`.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// A device's ID: the SHA-256 of its certificate.
pub type DeviceId = [u8; 32];

const SEQUENCE: u8 = 0x30;
const ED25519: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match contents.len() {
        len @ 0..0x80 => out.push(len as u8),
        len @ 0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

/// An end's certificate and its key.
#[derive(Clone)]
pub struct Identity {
    pub cert: Vec<u8>,
    seed: [u8; 32],
}

impl Identity {
    /// The certificate of the key of `seed`: the same bytes each time.
    pub fn of_seed(seed: [u8; 32]) -> Identity {
        let key = SigningKey::from_bytes(&seed);
        let spki =
            tlv(SEQUENCE, &[&ED25519[..], &tlv(0x03, &[&[0u8][..], key.verifying_key().as_bytes()].concat())].concat());
        // 2026-01-01 to 2099-12-31: the relay reads no date.
        let validity = tlv(SEQUENCE, &[tlv(0x17, b"260101000000Z"), tlv(0x18, b"20991231235959Z")].concat());
        let tbs = tlv(
            SEQUENCE,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                ED25519.to_vec(),
                tlv(SEQUENCE, &[]),
                validity,
                tlv(SEQUENCE, &[]),
                spki,
            ]
            .concat(),
        );
        let signature = key.sign(&tbs).to_bytes();
        let cert = tlv(SEQUENCE, &[tbs, ED25519.to_vec(), tlv(0x03, &[&[0u8][..], &signature].concat())].concat());
        Identity { cert, seed }
    }

    /// A fresh certificate, for a client of one run.
    pub fn fresh() -> Identity {
        Identity::of_seed(rand::random())
    }

    /// This end's device ID.
    pub fn id(&self) -> DeviceId {
        device_id(&self.cert)
    }

    /// The certificate and the key, as rustls presents them: podssh-ws's
    /// provider loads no private key, so the key signs here.
    fn certified(&self) -> rustls::sign::CertifiedKey {
        let key: Arc<dyn rustls::sign::SigningKey> = Arc::new(TlsKey(SigningKey::from_bytes(&self.seed)));
        rustls::sign::CertifiedKey::new(vec![CertificateDer::from(self.cert.clone())], key)
    }
}

/// The key as rustls signs with it: Ed25519, its one scheme.
#[derive(Debug)]
struct TlsKey(SigningKey);

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(TlsKey(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

impl rustls::sign::Signer for TlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// The device ID of a certificate.
pub fn device_id(cert: &[u8]) -> DeviceId {
    Sha256::digest(cert).into()
}

/// The verifier that holds a relay to its device ID.
#[derive(Debug)]
struct RelayId {
    id: DeviceId,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RelayId {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if device_id(end_entity.as_ref()) == self.id {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The TLS of a relay of device ID `relay`, with `me` as the client's
/// certificate: podssh-ws's provider, so no C.
pub fn config(relay: DeviceId, me: &Identity) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let algorithms = provider.signature_verification_algorithms;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RelayId { id: relay, algorithms }))
        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(me.certified())));
    config.alpn_protocols = vec![super::wire::ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_makes_the_same_certificate_and_rustls_reads_it() {
        let (a, b) = (Identity::of_seed([5; 32]), Identity::of_seed([5; 32]));
        assert_eq!(a.cert, b.cert);
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), Identity::of_seed([6; 32]).id());
        let der = CertificateDer::from(a.cert.clone());
        let parsed = rustls::server::ParsedCertificate::try_from(&der).expect("a certificate that rustls reads");
        assert_eq!(
            &parsed.subject_public_key_info().as_ref()[12..],
            SigningKey::from_bytes(&[5; 32]).verifying_key().as_bytes()
        );
        assert!(config([0; 32], &a)
            .expect("rustls takes the key and the certificate")
            .client_auth_cert_resolver
            .has_certs());
    }
}
