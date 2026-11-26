//! The certificates of the role's TLS in `relay_serve_h2`: a CA and a leaf
//! for a name, made with rcgen over a P-256 key of p256.

use base64::Engine as _;

/// A P-256 key of p256, for rcgen's certificates, and its PKCS #8 in PEM.
struct Key {
    signing: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing, public }
    }

    fn pkcs8_pem(&self) -> String {
        // SEQUENCE { 0, { id-ecPublicKey, prime256v1 }, OCTET STRING {
        // SEQUENCE { 1, OCTET STRING (32 bytes) } } }
        #[rustfmt::skip]
        const HEAD: [u8; 35] = [
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
            0x01, 0x04, 0x20,
        ];
        let mut der = HEAD.to_vec();
        der.extend_from_slice(&self.signing.to_bytes());
        pem("PRIVATE KEY", &der)
    }
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn serial() -> rcgen::SerialNumber {
    // With no crypto feature, rcgen draws no serial number of its own.
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// A leaf for `name` and its key, as PEM, and the CA that signed it.
pub fn certificates(name: &str) -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-h2-ca");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (pem("CERTIFICATE", leaf.der()), leaf_key.pkcs8_pem(), pem("CERTIFICATE", ca_cert.der()))
}
