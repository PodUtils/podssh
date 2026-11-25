//! A refused certificate in plain words (T-944): rustls writes the most of
//! its `CertificateError` variants, and each error of rustls-webpki inside
//! `Other(OtherError(..))`, as their `Debug` names, which `relay status` and
//! each other road then said ("invalid peer certificate:
//! Other(OtherError(CaUsedAsEndEntity))"). One table gives each name its
//! words; a name that a later rustls adds keeps its name, after words that
//! say a certificate was refused.

/// The words that rustls puts before the refusal of a certificate.
const PREFIX: &str = "invalid peer certificate: ";

/// The words of a certificate that is not well formed.
const MALFORMED: &str = "a certificate that is not well formed";
/// The words of a signature that does not verify.
const SIGNATURE: &str = "a certificate whose signature does not verify";
/// The words of an algorithm that podssh does not take.
const ALGORITHM: &str = "a certificate signed with an algorithm that podssh does not take";
/// The words of a certificate that is not for a TLS server.
const PURPOSE: &str = "a certificate that is not for a TLS server";
/// The words of a revocation list that cannot be used.
const CRL: &str = "a certificate revocation list that podssh cannot use";
/// The words of a chain that is too long or too complex to check.
const CHAIN: &str = "a chain of certificates too long or too complex to check";

/// Each `Debug` name of rustls 0.23's `CertificateError` and of
/// rustls-webpki 0.103's `Error`, and its words.
#[rustfmt::skip]
pub const WORDS: &[(&str, &str)] = &[
    // rustls's CertificateError.
    ("BadEncoding", MALFORMED),
    ("Expired", "an expired certificate"),
    ("ExpiredContext", "an expired certificate"),
    ("NotValidYet", "a certificate that is not valid yet"),
    ("NotValidYetContext", "a certificate that is not valid yet"),
    ("Revoked", "a revoked certificate"),
    ("UnhandledCriticalExtension", "a certificate with a critical extension that podssh does not read"),
    ("UnknownIssuer", "a certificate that no trusted CA signed"),
    ("UnknownRevocationStatus", "a certificate whose revocation status is not known"),
    ("ExpiredRevocationList", "an expired certificate revocation list"),
    ("ExpiredRevocationListContext", "an expired certificate revocation list"),
    ("BadSignature", SIGNATURE),
    ("UnsupportedSignatureAlgorithm", ALGORITHM),
    ("UnsupportedSignatureAlgorithmContext", ALGORITHM),
    ("UnsupportedSignatureAlgorithmForPublicKeyContext", ALGORITHM),
    ("NotValidForName", "a certificate for another name"),
    ("NotValidForNameContext", "a certificate for another name"),
    ("InvalidPurpose", PURPOSE),
    ("InvalidPurposeContext", PURPOSE),
    ("InvalidOcspResponse", "a certificate with an OCSP response that is not valid"),
    ("ApplicationVerificationFailure", "a certificate that the application's own check refused"),
    // rustls-webpki's Error, which rustls gives as Other(OtherError(..)).
    ("BadDer", MALFORMED),
    ("BadDerTime", MALFORMED),
    ("CaUsedAsEndEntity", "a CA's certificate served as the server's own: the server must serve a certificate that its CA signed"),
    ("CertDistrusted", "a certificate that its trusted root no longer vouches for"),
    ("CertExpired", "an expired certificate"),
    ("CertNotValidForName", "a certificate for another name"),
    ("CertNotValidYet", "a certificate that is not valid yet"),
    ("CertRevoked", "a revoked certificate"),
    ("CrlExpired", "an expired certificate revocation list"),
    ("EmptyEkuExtension", PURPOSE),
    ("EndEntityUsedAsCa", "a server's certificate that signs another, as if it were a CA"),
    ("ExtensionValueInvalid", MALFORMED),
    ("InvalidCertValidity", MALFORMED),
    ("InvalidCrlNumber", CRL),
    ("InvalidNetworkMaskConstraint", "a CA's name constraint that is not well formed"),
    ("InvalidSerialNumber", MALFORMED),
    ("InvalidCrlSignatureForPublicKey", CRL),
    ("InvalidSignatureForPublicKey", SIGNATURE),
    ("IssuerNotCrlSigner", CRL),
    ("MalformedDnsIdentifier", MALFORMED),
    ("MalformedExtensions", MALFORMED),
    ("MalformedNameConstraint", "a CA's name constraint that is not well formed"),
    ("MaximumNameConstraintComparisonsExceeded", CHAIN),
    ("MaximumPathBuildCallsExceeded", CHAIN),
    ("MaximumPathDepthExceeded", CHAIN),
    ("MaximumSignatureChecksExceeded", CHAIN),
    ("NameConstraintViolation", "a certificate for a name that its CA may not sign"),
    ("PathLenConstraintViolated", "a chain longer than its CA allows"),
    ("RequiredEkuNotFound", PURPOSE),
    ("RequiredEkuNotFoundContext", PURPOSE),
    ("SignatureAlgorithmMismatch", SIGNATURE),
    ("TrailingData", MALFORMED),
    ("UnsupportedCertVersion", MALFORMED),
    ("UnsupportedCriticalExtension", "a certificate with a critical extension that podssh does not read"),
    ("UnsupportedCrlIssuingDistributionPoint", CRL),
    ("UnsupportedCrlVersion", CRL),
    ("UnsupportedDeltaCrl", CRL),
    ("UnsupportedIndirectCrl", CRL),
    ("UnsupportedNameType", "a certificate for a kind of name that podssh does not read"),
    ("UnsupportedRevocationReason", CRL),
    ("UnsupportedRevocationReasonsPartitioning", CRL),
    ("UnsupportedCrlSignatureAlgorithm", CRL),
    ("UnsupportedCrlSignatureAlgorithmContext", CRL),
    ("UnsupportedCrlSignatureAlgorithmForPublicKey", CRL),
    ("UnsupportedCrlSignatureAlgorithmForPublicKeyContext", CRL),
    ("UnsupportedSignatureAlgorithmForPublicKey", ALGORITHM),
];

/// `text` with the `Debug` name after "invalid peer certificate: " in
/// words: the innermost name of `Other(OtherError(NAME))` or `NAME`, up to
/// the end of that name's own parentheses. Text with no such name is kept.
pub fn plain(text: &str) -> String {
    let Some(at) = text.find(PREFIX) else { return text.to_string() };
    let start = at + PREFIX.len();
    let rest = &text[start..];
    let inner = rest.strip_prefix("Other(OtherError(").unwrap_or(rest);
    let name_len = inner.bytes().take_while(u8::is_ascii_alphanumeric).count();
    let name = &inner[..name_len];
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        return text.to_string();
    }
    // The end of the Debug form: its parentheses and braces closed.
    let wrapped = rest.len() - inner.len();
    let end = start + wrapped + debug_end(&inner[name_len..]) + name_len + closing(wrapped);
    let end = end.min(text.len());
    let words = match WORDS.iter().find(|(known, _)| *known == name) {
        Some((_, words)) => (*words).to_string(),
        None => format!("a certificate that TLS refused ({name})"),
    };
    format!("{}{words}{}", &text[..start], &text[end..])
}

/// How many bytes of `after` (the text after a name) belong to its `Debug`
/// form: a balanced `(...)` or ` { ... }` right after the name.
fn debug_end(after: &str) -> usize {
    let open = match after.as_bytes().first() {
        Some(b'(') => 0,
        _ if after.starts_with(" {") => 1,
        _ => return 0,
    };
    let mut depth = 0usize;
    for (i, b) in after.bytes().enumerate().skip(open) {
        match b {
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    after.len()
}

/// The closing parentheses of `Other(OtherError(`, when the name was in one.
fn closing(wrapped: usize) -> usize {
    if wrapped > 0 {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{CertificateError, Error};

    /// Each name of the table, alone and in `Other(OtherError(..))`, comes
    /// out in words with no `Debug` name, and the text after it is kept; each
    /// variant of rustls's own that has no fields is in the table.
    #[test]
    fn each_refused_certificate_is_said_in_words() {
        for (name, words) in WORDS {
            for text in [format!("{PREFIX}{name}"), format!("{PREFIX}Other(OtherError({name}))")] {
                let said = plain(&format!("{text}; a hint"));
                assert_eq!(said, format!("{PREFIX}{words}; a hint"), "{text}");
            }
        }
        let own = [
            CertificateError::BadEncoding,
            CertificateError::Expired,
            CertificateError::NotValidYet,
            CertificateError::Revoked,
            CertificateError::UnhandledCriticalExtension,
            CertificateError::UnknownIssuer,
            CertificateError::UnknownRevocationStatus,
            CertificateError::ExpiredRevocationList,
            CertificateError::BadSignature,
            CertificateError::NotValidForName,
            CertificateError::InvalidPurpose,
            CertificateError::InvalidOcspResponse,
            CertificateError::ApplicationVerificationFailure,
        ];
        for error in own {
            let text = Error::InvalidCertificate(error).to_string();
            let said = plain(&text);
            assert!(said.starts_with(PREFIX) && !said.contains("Error"), "{text} -> {said}");
            assert!(WORDS.iter().any(|(_, words)| said.ends_with(words)), "{text} -> {said}");
        }
    }

    /// A name with fields loses them too; a name that the table lacks keeps
    /// its name after words; text with no refusal is kept.
    #[test]
    fn fields_go_and_an_unknown_name_is_kept() {
        let with = format!("{PREFIX}Other(OtherError(TrailingData(Certificate))) at the relay");
        assert_eq!(plain(&with), format!("{PREFIX}{MALFORMED} at the relay"));
        let braces = format!("{PREFIX}CertExpired {{ time: 1, not_after: 2 }}");
        assert_eq!(plain(&braces), format!("{PREFIX}an expired certificate"));
        assert_eq!(plain(&format!("{PREFIX}NewKind")), format!("{PREFIX}a certificate that TLS refused (NewKind)"));
        for kept in ["connection reset", "invalid peer certificate: certificate expired: at 1", ""] {
            assert_eq!(plain(kept), kept);
        }
    }
}
