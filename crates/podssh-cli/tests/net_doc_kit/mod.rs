//! A server of a net's signed document for a test of `--net-url` (T-715,
//! T-902): TLS of a CA of the test, which `SSL_CERT_FILE` names, for
//! [`NAME`], with one answer for each connection as the test sets it, and
//! each request counted. The CA and the leaf are rcgen's, signed by p256's
//! keys, as `node_net_url.rs` makes its own.

// Each test file uses a part of the kit.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The server's name; the test maps it to 127.0.0.1 by `PODSSH_RELAY_ADDR`.
pub const NAME: &str = "net-a.test";

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A P-256 key of p256, for rcgen's certificates and the server's key.
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

    /// SEC1's `EC PRIVATE KEY`, its curve named.
    fn pem(&self) -> String {
        let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x20];
        body.extend_from_slice(self.signing.to_bytes().as_slice());
        body.extend_from_slice(&[0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        pem("EC PRIVATE KEY", &der)
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

fn serial() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// A CA of the test, and a leaf of it for [`NAME`] with its key: each as PEM.
pub fn ca_and_leaf() -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name = rcgen::DistinguishedName::new();
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh test CA net-doc");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(ca, &ca_key)).unwrap();
    (pem("CERTIFICATE", ca_cert.der()), pem("CERTIFICATE", leaf.der()), leaf_key.pem())
}

/// The document's server: one answer for each connection, a status and a
/// body, as the test sets it now; each request counted.
pub struct Server {
    pub port: u16,
    answer: Arc<Mutex<(u16, Vec<u8>)>>,
    asked: Arc<Mutex<usize>>,
}

impl Server {
    pub fn start(rt: &tokio::runtime::Runtime, cert: &str, key: &str) -> Server {
        let alpn = [podssh_ws::tls_server::HTTP1];
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &alpn).expect("the TLS");
        let answer = Arc::new(Mutex::new((503u16, Vec::new())));
        let asked = Arc::new(Mutex::new(0));
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (served, heard) = (answer.clone(), asked.clone());
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, served, heard) = (acceptor.clone(), served.clone(), heard.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let (mut head, mut chunk) = (Vec::new(), [0u8; 1024]);
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    *heard.lock().unwrap() += 1;
                    let (status, body) = served.lock().unwrap().clone();
                    let head = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: \
                         close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(&[head.into_bytes(), body].concat()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Server { port, answer, asked }
    }

    pub fn answer(&self, status: u16, body: &[u8]) {
        *self.answer.lock().unwrap() = (status, body.to_vec());
    }

    pub fn asked(&self) -> usize {
        *self.asked.lock().unwrap()
    }
}
