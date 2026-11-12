//! TLS 1.3 of the Hysteria 2 road, with the ALPN `h3` that its server's
//! HTTP/3 takes. A link with no pin is checked as each road of podssh is:
//! rustls's WebPKI verifier over the roots of podssh's trust (`--ca-file`),
//! for the name of `sni`. A link with `pinSHA256` names the server's own
//! certificate, as a server that its user runs often has one of its own
//! that no root signs: that certificate alone passes, whole, by the SHA-256
//! of its DER, as Hysteria's client compares it (`VerifyPeerCertificate`),
//! and each signature of the handshake is checked against its key. An
//! intermediate's pin is not taken, as Hysteria's client takes it: with no
//! chain checked, anybody could send that certificate. A certificate of
//! another digest is refused with the digest that it showed.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

use super::link::{hex, Check};
use crate::tls::Trust;

/// The ALPN of HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// The verifier that holds the server to its pinned certificate.
#[derive(Debug)]
pub struct PinnedLeaf {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
    /// The digest of a refused certificate, for the line of the refusal.
    refused: Mutex<Option<String>>,
}

impl PinnedLeaf {
    pub fn new(pin: [u8; 32]) -> PinnedLeaf {
        let algorithms = crate::crypto::provider().signature_verification_algorithms;
        PinnedLeaf { pin, algorithms, refused: Mutex::new(None) }
    }

    /// The digest of the certificate that a handshake refused, once one did.
    pub fn refused(&self) -> Option<String> {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let seen: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if seen == self.pin {
            return Ok(ServerCertVerified::assertion());
        }
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(hex(&seen));
        Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
    }

    /// Never asked: the configuration offers TLS 1.3 alone, as QUIC takes
    /// it (RFC 9001, section 4.2); checked as rustls checks one all the same.
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

/// The TLS of `check`: the roots of `trust`, or the pin; and the pinning
/// verifier, which says what it refused.
pub fn config(check: &Check, trust: &Trust) -> Result<(Arc<ClientConfig>, Option<Arc<PinnedLeaf>>), String> {
    let provider = Arc::new(crate::crypto::provider());
    match check {
        Check::Roots => {
            let roots = crate::tls::roots_for(trust).map_err(|e| format!("the trust of the server's TLS: {e}"))?;
            let tls = pod_quic::connect::tls(provider, Arc::new(roots.roots), &[ALPN]).map_err(|e| e.to_string())?;
            Ok((tls, None))
        }
        Check::Pin(pin) => {
            let verifier = Arc::new(PinnedLeaf::new(*pin));
            let mut tls = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| format!("QUIC's TLS: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth();
            tls.alpn_protocols = vec![ALPN.to_vec()];
            Ok((Arc::new(tls), Some(verifier)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_pinned_certificate_passes_and_a_refusal_keeps_its_digest() {
        let (own, other) = (b"the server's own DER".to_vec(), b"another DER".to_vec());
        let pin: [u8; 32] = Sha256::digest(&own).into();
        let verifier = PinnedLeaf::new(pin);
        let name = ServerName::try_from("h.example").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_793_000_000));
        let check = |der: &[u8]| verifier.verify_server_cert(&CertificateDer::from(der), &[], &name, &[], now);
        assert!(check(&own).is_ok(), "the pinned certificate");
        assert_eq!(verifier.refused(), None);
        assert!(check(&other).is_err(), "a certificate of another digest");
        let seen: [u8; 32] = Sha256::digest(&other).into();
        assert_eq!(verifier.refused(), Some(hex(&seen)));
        let (tls, kept) = config(&Check::Pin(pin), &Trust::Default).unwrap();
        assert_eq!((tls.alpn_protocols.clone(), kept.is_some()), (vec![b"h3".to_vec()], true));
        assert!(!verifier.supported_verify_schemes().is_empty());
    }
}
