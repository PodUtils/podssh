//! `podssh node --net-url URL --net-owner KEY` (T-715): a server of the
//! test's, over TLS of a CA of the test that SSL_CERT_FILE names, serves the
//! net's document that `podssh net` signed. A node whose first fetch fails
//! with no copy does not start (78); one that fetches takes the document,
//! which `net ls` and `status --net` show; a newer serial that drops a
//! member is taken in its place; a server that fails leaves the copy read;
//! a document of another owner and a redirect are refused (78). No line
//! shows the URL's path. The node runs on `--carrier stdio` with stdin at
//! its end, so that it reaches no relay and no public road. The door that
//! follows within the TTL, and closes past the stale window, is the paused
//! clock's of `net::remote`'s tests. Unix, as the certificates' files are.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::identity::Identity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NAME: &str = "net-a.test";
const WAIT: Duration = Duration::from_secs(30);
/// The secret of the URL's path, which no line may show.
const SECRET: &str = "fleet-SECRET-path";

/// The test's directory, gone when it ends, passed or not.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let name = format!("podssh-net-url-{tag}-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let dir = std::env::temp_dir().join(name);
    podssh_relay::cache::private_dir(&dir).unwrap();
    podssh_relay::cache::private_dir(&dir.join("cache")).unwrap();
    Scratch(dir)
}

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

/// A CA of the test, and a leaf of it for NAME with its key: each as PEM.
fn ca_and_leaf() -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name = rcgen::DistinguishedName::new();
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh test CA net-url");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(ca, &ca_key)).unwrap();
    (pem("CERTIFICATE", ca_cert.der()), pem("CERTIFICATE", leaf.der()), leaf_key.pem())
}

/// An answer of the document's server: a status, a body, and a Location or
/// none.
type Answer = (u16, Vec<u8>, Option<String>);

/// The document's server: one answer for each connection, as the test sets
/// it now; each request counted.
struct Server {
    port: u16,
    answer: Arc<Mutex<Answer>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(rt: &tokio::runtime::Runtime, cert: &str, key: &str) -> Server {
        let alpn = [podssh_ws::tls_server::HTTP1];
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &alpn).expect("the TLS");
        let answer = Arc::new(Mutex::new((503u16, Vec::new(), None)));
        let asked = Arc::new(Mutex::new(Vec::new()));
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
                    let first = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
                    heard.lock().unwrap().push(first);
                    let (status, body, location) = served.lock().unwrap().clone();
                    let location = location.map(|to| format!("Location: {to}\r\n")).unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{location}{}",
                        body.len(),
                        "Connection: close\r\n\r\n"
                    );
                    let _ = tls.write_all(&[head.into_bytes(), body].concat()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Server { port, answer, asked }
    }

    fn answer(&self, status: u16, body: &[u8], location: Option<&str>) {
        *self.answer.lock().unwrap() = (status, body.to_vec(), location.map(String::from));
    }

    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

/// `podssh` with HOME and the cache under `home`, no proxy, no settings,
/// the test's CA and the server's address.
fn podssh(home: &Path, ca: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_NET"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("PODSSH_CACHE_DIR", home.join("cache")).env("PODSSH_SSH_CONFIG", "none");
    cmd.env("PODSSH_SETTINGS", "none").env("SSL_CERT_FILE", ca).env("PODSSH_RELAY_ADDR", format!("{NAME}=127.0.0.1"));
    cmd.stdin(Stdio::null());
    cmd
}

/// What a run gave: its exit code (None when it was stopped), and stderr.
fn ran(cmd: &mut Command) -> (Option<i32>, String, String) {
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code(), text(&out.stdout), text(&out.stderr))
}

/// The node `lab` with its net at `url` of `owner`, on a carrier whose
/// stream is at its end: its exit code and stderr, within [`WAIT`].
fn node(home: &Path, ca: &Path, url: &str, owner: &str) -> (Option<i32>, String) {
    node_until(home, ca, url, owner, "127.0.0.1:9", &[], "podssh node: lab: the net from")
}

/// [`node`] in front of `target`, with `extra` flags, until its log holds
/// `until`; a line past the node's check of its target needs a target that
/// answers.
fn node_until(
    home: &Path,
    ca: &Path,
    url: &str,
    owner: &str,
    target: &str,
    extra: &[&str],
    until: &str,
) -> (Option<i32>, String) {
    let log = home.join(format!("node-{:08x}.log", rand::random::<u32>()));
    let mut child = podssh(home, ca)
        .args(["node", "lab", target, "--carrier", "stdio", "--net-url", url, "--net-owner", owner])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let end = Instant::now() + WAIT;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        let said = std::fs::read_to_string(&log).unwrap_or_default();
        // Past its start the node's road is not this test's: the net is taken.
        if said.contains(until) || Instant::now() >= end {
            std::thread::sleep(Duration::from_millis(200));
            let _ = child.kill();
            break child.wait().unwrap().code();
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    (code, std::fs::read_to_string(&log).unwrap())
}

/// An owner's key made by podssh keygen: its file, and its public line.
fn owner_key(home: &Path, ca: &Path, name: &str) -> (PathBuf, String) {
    let path = home.join(name);
    let (code, _, err) = ran(podssh(home, ca).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]).arg(&path));
    assert_eq!(code, Some(0), "podssh keygen: {err}");
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (path, public.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
}

/// `podssh net ARGS` on the owner's own document `doc`, signed by `key`.
fn owner_net(home: &Path, ca: &Path, doc: &Path, key: &Path, args: &[&str]) {
    let mut cmd = podssh(home, ca);
    let (code, _, err) = ran(cmd.env("PODSSH_NET", doc).arg("net").args(args).arg("--owner-key").arg(key));
    assert_eq!(code, Some(0), "podssh net {args:?}: {err}");
}

fn key_hex(seed: u8) -> String {
    Identity::from_seed(&[seed; 32]).public().hex()
}

#[test]
fn a_node_takes_its_net_from_a_url_by_its_owner_alone() {
    let home = scratch("node");
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (ca, cert, key) = ca_and_leaf();
    let ca_file = home.0.join("ca.pem");
    std::fs::write(&ca_file, &ca).unwrap();
    let server = Server::start(&rt, &cert, &key);
    let url = format!("https://{NAME}:{}/{SECRET}?k=1", server.port);
    let shown = format!("https://{NAME}:{}/...", server.port);
    let h = &home.0;

    // The owner's net, on its own host: m31 and m32.
    let (owner, public) = owner_key(h, &ca_file, "owner");
    let doc = h.join("owner.doc");
    owner_net(h, &ca_file, &doc, &owner, &["init", "fleet"]);
    owner_net(h, &ca_file, &doc, &owner, &["add", "m31", &key_hex(0x31)]);
    owner_net(h, &ca_file, &doc, &owner, &["add", "m32", &key_hex(0x32)]);

    // The first fetch fails, and no copy is held: no start (78).
    server.answer(503, b"", None);
    let (code, said) = node(h, &ca_file, &url, &public);
    assert_eq!(code, Some(78), "{said}");
    assert!(said.contains(&format!("--net-url {shown}: HTTP 503")) && !said.contains("SECRET"), "{said}");

    // The document: taken, and each door reads it.
    server.answer(200, &std::fs::read(&doc).unwrap(), None);
    let (_, said) = node(h, &ca_file, &url, &public);
    assert!(said.contains(&format!("the net from {shown}: serial 3, the first held here")), "{said}");
    assert!(!said.contains("SECRET"), "{said}");
    let (code, out, err) = ran(podssh(h, &ca_file).args(["net", "ls"]));
    assert!(code == Some(0) && out.contains("m31\t") && out.contains("m32\t"), "{out}{err}");
    let (_, out, _) = ran(podssh(h, &ca_file).args(["status", "--net"]));
    let line: serde_json::Value = serde_json::from_str(out.trim()).expect("status's line");
    let fetched = &line["net"]["url"];
    assert_eq!((&fetched["url"], &fetched["serial"]), (&serde_json::json!(shown), &serde_json::json!(3)), "{line}");
    assert_eq!((&fetched["stale"], &fetched["closed"]), (&serde_json::json!(false), &serde_json::json!(false)));
    assert!(!out.contains("SECRET"), "{out}");

    // The owner drops m32: the newer serial is taken in place of the old.
    owner_net(h, &ca_file, &doc, &owner, &["rm", "m32"]);
    server.answer(200, &std::fs::read(&doc).unwrap(), None);
    let (_, said) = node(h, &ca_file, &url, &public);
    assert!(said.contains("serial 4, in place of 3"), "{said}");
    let (_, out, _) = ran(podssh(h, &ca_file).args(["net", "ls"]));
    assert!(out.contains("m31\t") && !out.contains("m32\t"), "{out}");

    // The node as m31, with no --allow: the net is its whole door, so it says
    // the net's line, and never that the pair's token lets each in (T-941).
    let m31 = h.join("m31.key");
    std::fs::write(&m31, format!("{}\n", "31".repeat(32))).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&m31, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    server.answer(200, &std::fs::read(&doc).unwrap(), None);
    let key_flag = ["--key", m31.to_str().unwrap()];
    // A target that answers, as the node dials it before its door's lines.
    let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = open.local_addr().unwrap().to_string();
    let (_, said) = node_until(h, &ca_file, &url, &public, &target, &key_flag, "grants used once");
    drop(open);
    assert!(said.contains("podssh node: lab: a member of the net fleet as m31"), "{said}");
    assert!(!said.contains("each operator with the pair's connect token may come in"), "{said}");

    // The server fails: the node starts on its copy, which it says.
    server.answer(503, b"", None);
    let (code, said) = node(h, &ca_file, &url, &public);
    assert_ne!(code, Some(78), "{said}");
    assert!(said.contains("HTTP 503") && said.contains("its copy of"), "{said}");

    // Another owner's document, on a host with no copy: refused (78).
    let other_home = scratch("other");
    let o = &other_home.0;
    let (other, _) = owner_key(o, &ca_file, "other");
    let other_doc = o.join("other.doc");
    owner_net(o, &ca_file, &other_doc, &other, &["init", "fleet"]);
    server.answer(200, &std::fs::read(&other_doc).unwrap(), None);
    let (code, said) = node(o, &ca_file, &url, &public);
    assert_eq!(code, Some(78), "{said}");
    assert!(said.contains("--net-owner"), "{said}");
    let (_, out, _) = ran(podssh(o, &ca_file).args(["net", "ls"]));
    assert!(out.is_empty(), "nothing is kept: {out}");

    // A redirect is one GET more (Q105): refused, never followed.
    let before = server.asked();
    server.answer(302, b"", Some(&format!("https://{NAME}:{}/elsewhere", server.port)));
    let (code, said) = node(o, &ca_file, &url, &public);
    assert_eq!(code, Some(78), "{said}");
    assert!(said.contains("does not follow"), "{said}");
    assert_eq!(server.asked(), before + 1, "one GET for the fetch");
}
