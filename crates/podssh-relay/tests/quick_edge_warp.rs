//! The quick tunnel's edge inside WARP's tunnel (T-374), on the loopback:
//! the road's dial (pod-warp's `WarpNet` in a run, a dial of the test here,
//! as pod-warp's own tests prove the tunnel) carries the node's TCP stream
//! to the edge's port 7844 at an address that only its tunnel reaches;
//! there a stand-in of the quick tunnel's edge, whose TLS names
//! `h2.cftunnel.com` under a CA of the test, is the client of HTTP/2, as
//! cloudflared's edge is (`quick_harness`). The node registers, and a
//! visitor's WebSocket passes both ways. Planted: a stream sent past the
//! dial finds no edge at that address, and the edge's stand-in sees no
//! connection.
#![cfg(feature = "warp")]

mod quick_harness;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use pod_core::{BoxFuture, Class, Connected, Dial, Failure, Stage, Target};
use podssh_relay::quick::edge::{self, Edge};
use podssh_relay::quick::edge_warp;
use podssh_relay::quick::serve::Step;
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::Trust;
use quick_harness::{echo, node_with, read_frame, register, visitor, LIMIT};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// The edge's address inside the tunnel: TEST-NET-2, which no network of
/// this host routes.
fn inside() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), edge::port())
}

/// The tunnel of the test: [`inside`] goes to `outside` on the loopback,
/// and no other target is reached; it counts the streams that it carried.
struct Tunnel {
    outside: Option<SocketAddr>,
    carried: AtomicUsize,
}

impl Dial for Tunnel {
    fn label(&self) -> String {
        "WARP of the test".into()
    }

    fn dial<'a>(
        &'a self,
        target: &'a Target,
        _deadline: tokio::time::Instant,
    ) -> BoxFuture<'a, Result<Connected, Failure>> {
        Box::pin(async move {
            let to = match (target, self.outside) {
                (Target::Addr(at), Some(outside)) if *at == inside() => outside,
                _ => {
                    return Err(Failure::new(
                        Stage::Warp,
                        Class::Unavailable,
                        format!("no route to {target} inside the tunnel"),
                    ))
                }
            };
            let tcp = TcpStream::connect(to).await.map_err(|e| Failure::io(Stage::Connect, e))?;
            self.carried.fetch_add(1, Ordering::SeqCst);
            Ok(Connected::new(Box::new(tcp)))
        })
    }
}

/// A P-256 key, for rcgen's certificates and for rustls's handshake.
struct Key {
    signing: Arc<p256::ecdsa::SigningKey>,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing: Arc::new(signing), public }
    }
}

/// An ECDSA signature in DER, as X.509 and TLS carry it.
fn sign(key: &p256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
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
        Ok(sign(&self.signing, message))
    }
}

/// The edge's TLS key, for rustls.
#[derive(Debug)]
struct TlsKey(Arc<p256::ecdsa::SigningKey>);

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        offered.contains(&scheme).then(|| Box::new(TlsKey(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

impl rustls::sign::Signer for TlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(sign(&self.0, message))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// The stand-in of the quick tunnel's edge: TLS for `h2.cftunnel.com` on
/// the loopback, each connection handed to the test, which is its client
/// of HTTP/2; and the trust of the test's CA, for the node.
type Accepted = mpsc::UnboundedReceiver<tokio_rustls::server::TlsStream<TcpStream>>;

async fn quick_edge() -> (SocketAddr, Accepted, Trust) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-edge-ca");
    // With no crypto feature, rcgen draws no serial number of its own.
    ca.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, &ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![edge::server_name().to_string()]).unwrap();
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    let certified = rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], Arc::new(TlsKey(leaf_key.signing)));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, conns) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = accepted.send(tls);
            }
        }
    });
    let mut store = rustls::RootCertStore::empty();
    store.add(ca_cert.der().clone()).unwrap();
    let roots = podssh_ws::tls::TlsRoots { roots: store, source: "the test's CA".into(), count: 1 };
    let trust = Trust::caller(podssh_ws::tls::client_config(&roots).unwrap()).unwrap();
    (addr, conns, trust)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_registers_through_warp_s_tunnel_and_a_visitor_passes() {
    let (edge_addr, mut conns, trust) = quick_edge().await;
    let tunnel = Tunnel { outside: Some(edge_addr), carried: AtomicUsize::new(0) };
    // The edge by its address inside the tunnel, as its SRV record names
    // regions that the tunnel reaches.
    let found = Edge { regions: vec![inside().ip().to_string()], port: edge::port(), fixed: None };
    let tls = tokio::time::timeout(LIMIT, edge_warp::connect(&tunnel, &found, &trust))
        .await
        .expect("in time")
        .expect("the edge's TLS inside WARP's tunnel");
    assert_eq!(tunnel.carried.load(Ordering::SeqCst), 1, "the stream to the edge went through the tunnel");
    let (mut steps, stop, served) = node_with(tls, echo);

    // The edge's end: the client of HTTP/2, on the connection that came
    // through the tunnel.
    let edge_io = tokio::time::timeout(LIMIT, conns.recv()).await.expect("a connection in time").unwrap();
    let (mut client, connection) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(connection);
    let (_to_node, _from_node) = register(&mut client, &mut steps).await;
    let (mut visitor_out, mut visitor_in) = visitor(&mut client).await;
    assert_eq!(steps.recv().await, Some(Step::Visitor));
    let message = Frame { fin: true, opcode: 0x2, payload: b"through warp".to_vec() };
    visitor_out.send_data(Bytes::from(frame::encode(&message, Role::Client, [3, 1, 4, 1])), false).unwrap();
    let echoed = read_frame(&mut visitor_in).await;
    assert_eq!((echoed.opcode, echoed.payload.as_slice()), (0x2, &b"through warp"[..]));
    assert!(conns.try_recv().is_err(), "the edge's stand-in saw one connection alone");

    stop.send(()).unwrap();
    drop((visitor_out, visitor_in));
    let _ = tokio::time::timeout(LIMIT, served).await;
}

/// The edge at an address that the tunnel does not reach gives the node a
/// line that names the road and the region, within the dial's limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_that_the_tunnel_does_not_reach_is_named() {
    let (_, _conns, trust) = quick_edge().await;
    let tunnel = Tunnel { outside: None, carried: AtomicUsize::new(0) };
    let found = Edge { regions: vec![inside().ip().to_string()], port: edge::port(), fixed: None };
    let why = match edge_warp::connect(&tunnel, &found, &trust).await {
        Ok(_) => panic!("an edge where the tunnel reaches none"),
        Err(why) => why,
    };
    assert!(why.contains("inside WARP's tunnel") && why.contains("198.51.100.7:7844"), "{why}");
    assert_eq!(tunnel.carried.load(Ordering::SeqCst), 0);
}
