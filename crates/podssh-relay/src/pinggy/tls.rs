//! The client's TLS of the Pinggy road (T-548), which pins the node's key.
//! A free tunnel's name changes each hour, so a certificate of a CA for each
//! name would spend its limits (T-548's Decision): the node's certificate
//! is its own, self-signed, and no root vouches for it. So the client holds
//! the node to the key that the node says beside its tunnel's name: the
//! SHA-256 of the certificate's SubjectPublicKeyInfo, as HPKP named a key,
//! which stays across the node's names and restarts. A certificate of
//! another key is a stranger at the name (Pinggy gives a name to the next
//! tunnel after its hour) or a proxy that ends TLS itself, and is refused
//! with the key it showed; its chain, its name and its dates are not read,
//! as no CA is asked. The end-to-end channel above the layer still checks
//! the node's own key on each link. podssh-ws's provider, so no C and no
//! other crypto; WARP's road pins its endpoint the same way (T-352).

use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use podssh_ws::Trust;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::Digest as _;

/// The word before a pin's digest, as OpenSSH names a key's.
pub const PIN_PREFIX: &str = "SHA256:";

/// The SHA-256 of a certificate's SubjectPublicKeyInfo, whole (its outer
/// SEQUENCE too, as `openssl pkey -pubin -outform der` writes it).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    /// The pin of a SubjectPublicKeyInfo's DER.
    pub fn of_spki(spki: &[u8]) -> Pin {
        Pin(sha2::Sha256::digest(spki).into())
    }

    /// The pin of an X.509 certificate's key; none when it is not one.
    pub fn of_certificate(der: &[u8]) -> Option<Pin> {
        let der = CertificateDer::from(der);
        let parsed = ParsedCertificate::try_from(&der).ok()?;
        Some(Pin::of_spki(parsed.subject_public_key_info().as_ref()))
    }

    /// `SHA256:` and 43 characters of base64, with or without its `=`.
    pub fn parse(text: &str) -> Result<Pin, String> {
        let bad = || format!("a pin is {PIN_PREFIX} and the 43 characters of base64 that the node says");
        let digest = text.trim().strip_prefix(PIN_PREFIX).ok_or_else(bad)?.trim_end_matches('=');
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(digest).map_err(|_| bad())?;
        Ok(Pin(bytes.try_into().map_err(|_| bad())?))
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PIN_PREFIX}{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.0))
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// The verifier that holds the node to its pinned key, and checks each
/// signature of the handshake against that key's certificate.
#[derive(Debug)]
pub struct PinnedNode {
    pin: Pin,
    algorithms: WebPkiSupportedAlgorithms,
    /// What a refused certificate showed, for the line of the refusal.
    refused: Mutex<Option<String>>,
}

impl PinnedNode {
    /// The verifier of the node whose key is `pin`.
    pub fn new(pin: Pin) -> PinnedNode {
        let algorithms = podssh_ws::crypto::provider().signature_verification_algorithms;
        PinnedNode { pin, algorithms, refused: Mutex::new(None) }
    }

    /// The key of the certificate that a handshake refused, once one did.
    pub fn refused(&self) -> Option<String> {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl ServerCertVerifier for PinnedNode {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let seen = Pin::of_certificate(end_entity.as_ref());
        let shown = match seen {
            Some(seen) if seen == self.pin => return Ok(ServerCertVerified::assertion()),
            Some(seen) => seen.to_string(),
            None => "a certificate whose key cannot be read".to_string(),
        };
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(shown);
        Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
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

/// A client's configuration that pins the node's key `pin`: TLS 1.3 and
/// 1.2, no ALPN, no client certificate; and its verifier, which says what
/// it refused.
pub fn config(pin: Pin) -> Result<(Arc<ClientConfig>, Arc<PinnedNode>), String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let verifier = Arc::new(PinnedNode::new(pin));
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("the Pinggy road's TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    Ok((Arc::new(config), verifier))
}

/// The trust of one link to the node of `pin`: [`config`], used as it is.
pub fn trust(pin: Pin) -> Result<(Trust, Arc<PinnedNode>), String> {
    let (config, verifier) = config(pin)?;
    let trust = Trust::caller(config).map_err(|e| format!("the Pinggy road's TLS: {e}"))?;
    Ok((trust, verifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate of a new P-256 key, as the node makes one.
    fn certificate() -> Vec<u8> {
        struct Key(p256::ecdsa::SigningKey, Vec<u8>);
        impl rcgen::PublicKeyData for Key {
            fn der_bytes(&self) -> &[u8] {
                &self.1
            }
            fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
                &rcgen::PKCS_ECDSA_P256_SHA256
            }
        }
        impl rcgen::SigningKey for Key {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = self.0.sign(message);
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let key = Key(signing, public);
        let mut params = rcgen::CertificateParams::new(vec!["podssh-node.invalid".to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1]));
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn the_configuration_offers_no_alpn_and_the_pin_reads_back_as_the_node_says_it() {
        let pin = Pin::of_certificate(&certificate()).expect("a certificate's key");
        let (config, verifier) = config(pin).unwrap();
        assert!(config.alpn_protocols.is_empty(), "Trust::caller refuses ALPN");
        assert!(trust(pin).is_ok());
        assert!(!verifier.supported_verify_schemes().is_empty());
        let text = pin.to_string();
        assert!(text.starts_with("SHA256:") && text.len() == 7 + 43, "{text}");
        assert_eq!(Pin::parse(&text), Ok(pin));
        assert_eq!(Pin::parse(&format!("{text}=")), Ok(pin), "base64's padding");
        for bad in ["", "SHA256:", "sha256:abc", &text[7..], "SHA256:!!!", &format!("{text}AAAA")] {
            assert!(Pin::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_pinned_key_passes_and_a_refusal_keeps_the_key_it_saw() {
        let (own, other) = (certificate(), certificate());
        let pin = Pin::of_certificate(&own).unwrap();
        let verifier = PinnedNode::new(pin);
        let name = ServerName::try_from("abc.a.pinggy.link").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_793_000_000));
        let check = |der: &[u8]| verifier.verify_server_cert(&CertificateDer::from(der), &[], &name, &[], now);
        assert!(check(&own).is_ok(), "the node's own certificate");
        assert_eq!(verifier.refused(), None);
        assert!(check(&other).is_err(), "a certificate of another key");
        let seen = Pin::of_certificate(&other).unwrap();
        assert_ne!(seen, pin);
        assert_eq!(verifier.refused(), Some(seen.to_string()));
        assert!(check(&[0x30, 0x00]).is_err(), "no certificate at all");
        assert_eq!(verifier.refused().as_deref(), Some("a certificate whose key cannot be read"));
    }
}
