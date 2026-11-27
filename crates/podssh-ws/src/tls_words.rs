//! A refused certificate in plain words (T-944): `pod-tls` of PodUtils/podcrates
//! (T-1409). `pod_tls::handshake_failure` and `pod_tls::handshake_error` say a
//! refused certificate in these words already; these aliases stay for callers
//! that rewrite a certificate refusal's text.

pub use pod_tls::{plain_certificate as plain, CERTIFICATE_WORDS as WORDS};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_tls_words_replace_rustls_and_webpki_debug_names() {
        const PREFIX: &str = "invalid peer certificate: ";
        assert_eq!(
            plain(&format!("{PREFIX}UnknownIssuer; a hint")),
            format!("{PREFIX}a certificate that no trusted CA signed; a hint")
        );
        let ca = plain(&format!("{PREFIX}Other(OtherError(CaUsedAsEndEntity))"));
        assert!(ca.contains("the certificate of a CA, served as the server's own"), "{ca}");
        assert!(!ca.contains("CaUsedAsEndEntity") && !ca.contains("OtherError"), "{ca}");
        assert!(WORDS.iter().any(|(name, _)| *name == "UnknownIssuer"));
        assert!(WORDS.iter().any(|(name, _)| *name == "CaUsedAsEndEntity"));
    }
}
