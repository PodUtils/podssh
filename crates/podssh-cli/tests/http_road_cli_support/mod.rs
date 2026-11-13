//! What `tests/http_road_cli.rs` runs against (T-319): `podssh relay serve`
//! on the loopback with a certificate of the run's own CA for relay-a.test;
//! in front of it, as `https_proxy`, the intercepting proxy of
//! `cloud_support`, which ends TLS for the relay's name with a CA of its
//! own (given to podssh with `--ca-file`), answers each request that asks
//! for an upgrade with a page of its own, and carries each other request to
//! the role over TLS of its own, one request on each connection, its body
//! held to its end, as proxies that end TLS do; the test's SSH server
//! (`ssh_harness`, through `throughput_harness::Session`); targets on the
//! loopback; and a run of podssh with its input, output and time limit.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cloud_support::{header, read_head, Handler, Proxy, Stream};
use crate::throughput_harness::{without_proxy, Session};

/// The relay's name, which only the proxy reaches.
pub const NAME: &str = "relay-a.test";
/// The proxy's words when it refuses an upgrade: no word of a relay's, so
/// that podssh reads the refusal as the way's.
pub const REFUSAL: &str = "WebSocket upgrades are not allowed by this proxy";
pub const MIB: usize = 1 << 20;
/// The bound of each wait of the setup.
const WAIT: Duration = Duration::from_secs(30);
/// The bound of each run of podssh.
const RUN_LIMIT: Duration = Duration::from_secs(240);

/// A P-256 key of p256, for rcgen's certificates and the role's `--key`.
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

    /// SEC1's `EC PRIVATE KEY`, its curve named, as `openssl ecparam` writes it.
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

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// With no crypto feature, rcgen draws no serial number of its own.
fn serial() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// The role's CA and its leaf for NAME, written in `dir`: the files of
/// `--cert` and `--key`, and the CA that the proxy trusts on its way to the
/// role. podssh never sees this CA: it trusts the proxy's alone.
fn role_certificate(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name = rcgen::DistinguishedName::new();
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh test CA of the HTTP road's role");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(ca, &ca_key)).unwrap();
    let (cert, key, ca_file) = (dir.join("role-cert.pem"), dir.join("role-key.pem"), dir.join("role-ca.pem"));
    std::fs::write(&cert, pem("CERTIFICATE", leaf.der())).unwrap();
    std::fs::write(&key, leaf_key.pem()).unwrap();
    // A key that others can read is no key a server should take.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&ca_file, pem("CERTIFICATE", ca_cert.der())).unwrap();
    (cert, key, ca_file)
}

/// What the proxy did: the upgrades that it refused, and the first line of
/// each request that it carried to the role.
#[derive(Debug, Default)]
pub struct Seen {
    pub upgrades: AtomicUsize,
    pub carried: Mutex<Vec<String>>,
}

impl Seen {
    /// The requests carried whose line holds `word`.
    pub fn count(&self, word: &str) -> usize {
        self.carried.lock().unwrap().iter().filter(|line| line.contains(word)).count()
    }
}

/// The role, the proxy in front of it, and the test's SSH server.
pub struct Bench {
    pub s: Session,
    pub proxy: Proxy,
    pub seen: Arc<Seen>,
    /// The proxy's own runtime, apart from the SSH server's, so that its
    /// TLS on both sides does not slow the server down; dropped last.
    rt: tokio::runtime::Runtime,
}

impl Bench {
    /// The role with `extra` flags of `podssh relay serve`, then the proxy.
    pub fn start(tag: &str, extra: &[&str]) -> Bench {
        let s = Session::start(tag);
        let (cert, key, role_ca) = role_certificate(&s.home);
        let (port_file, log) = (s.home.join("role-port"), s.home.join("role.log"));
        let serve = ["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--routes", "127.0.0.1"];
        let mut args: Vec<String> = serve.map(String::from).into();
        args.extend(extra.iter().map(|a| a.to_string()));
        for (flag, path) in [("--cert", &cert), ("--key", &key), ("--port-file", &port_file)] {
            args.extend([flag.to_string(), path.display().to_string()]);
        }
        let child = without_proxy(s.command(&args))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("podssh relay serve starts");
        s.keep(child);
        let deadline = Instant::now() + WAIT;
        let role = loop {
            if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
                break port;
            }
            let said = std::fs::read_to_string(&log).unwrap_or_default();
            assert!(Instant::now() < deadline, "the role did not start within {WAIT:?}: {said}");
            std::thread::sleep(Duration::from_millis(50));
        };
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
        let seen = Arc::new(Seen::default());
        let proxy = rt.block_on(Proxy::start(&s.home, handler(role, role_ca, seen.clone())));
        Bench { s, proxy, seen, rt }
    }

    /// `--relay-host` the relay's name, and `--ca-file` the proxy's CA.
    pub fn relay_flags(&self) -> Vec<String> {
        let ca = self.proxy.ca_file.display().to_string();
        ["--relay-host".to_string(), format!("{NAME}:443"), "--ca-file".into(), ca].into()
    }

    /// `podssh ARGS` through the proxy alone, in `form` of the road
    /// (`PODSSH_HTTP_ROAD`), or the default when `None`.
    pub fn podssh(&self, args: &[String], form: Option<&str>) -> Command {
        let mut cmd = without_proxy(self.s.command(args));
        for name in ["PODSSH_RELAY", "PODSSH_RELAY_TOKEN", "PODSSH_RELAY_LAYER", "PODSSH_HTTP_ROAD", "SSL_CERT_FILE"] {
            cmd.env_remove(name);
        }
        cmd.env("https_proxy", self.proxy.url());
        if let Some(form) = form {
            cmd.env("PODSSH_HTTP_ROAD", form);
        }
        cmd
    }

    /// The proxy refused the upgrade, and carried the road's requests of
    /// `form`: batches up and answers down on their own requests in the
    /// split form, exchanges and no batch of its own in the serial form.
    pub fn carried_in(&self, form: &str) {
        let lines = self.seen.carried.lock().unwrap().clone();
        assert!(self.seen.upgrades.load(Ordering::SeqCst) > 0, "the proxy refused an upgrade: {lines:?}");
        assert!(self.seen.count("/v1/http/open/") > 0, "the road opened through the proxy: {lines:?}");
        match form {
            "split" => assert!(self.seen.count("/up?") > 0 && self.seen.count("/down?") > 0, "{lines:?}"),
            _ => assert!(self.seen.count("/x?") > 0 && self.seen.count("/up?") == 0, "{lines:?}"),
        }
    }
}

/// The proxy's side of each connection that it ended TLS of.
fn handler(role: u16, role_ca: PathBuf, seen: Arc<Seen>) -> Handler {
    Arc::new(move |_host: String, stream: Stream| {
        let (role_ca, seen) = (role_ca.clone(), seen.clone());
        Box::pin(async move {
            let _ = carry(stream, role, &role_ca, &seen).await;
        })
    })
}

/// One request: refused when it asks for an upgrade; else its body read
/// whole, then the request on to the role on a connection of its own, and
/// the role's answer back as it comes, to the role's close.
async fn carry(mut client: Stream, role: u16, role_ca: &Path, seen: &Seen) -> std::io::Result<()> {
    let head = read_head(&mut client).await?;
    let first = head.lines().next().unwrap_or_default().to_string();
    if header(&head, "Upgrade").is_some() {
        seen.upgrades.fetch_add(1, Ordering::SeqCst);
        let top = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            REFUSAL.len()
        );
        client.write_all(format!("{top}{REFUSAL}").as_bytes()).await?;
        return client.shutdown().await;
    }
    seen.carried.lock().unwrap().push(first.clone());
    let length = header(&head, "Content-Length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let mut body = vec![0u8; length];
    client.read_exact(&mut body).await?;
    let mut forward = format!("{first}\r\n");
    for line in head.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "content-length" | "connection" | "keep-alive") {
            forward.push_str(&format!("{line}\r\n"));
        }
    }
    forward.push_str(&format!("Content-Length: {length}\r\nConnection: close\r\n\r\n"));
    let trust = podssh_ws::Trust::File(role_ca.to_path_buf());
    let direct = podssh_ws::ProxyChoice::Direct;
    let mut upstream = podssh_ws::client::open_tls("127.0.0.1", role, NAME, &trust, &direct, WAIT)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    upstream.write_all(forward.as_bytes()).await?;
    upstream.write_all(&body).await?;
    upstream.flush().await?;
    // An answer down streams: passed as it comes, never held to its end.
    let _ = tokio::io::copy(&mut upstream, &mut client).await;
    client.shutdown().await
}

/// A target on the loopback that sends back each byte, then ends its side
/// once the other side ended.
pub fn echo_target() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let Ok(mut back) = stream.try_clone() else { return };
                let mut from = stream;
                let _ = std::io::copy(&mut from, &mut back);
                let _ = back.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    port
}

/// A target on the loopback that sends `size` bytes, then reads to the end.
pub fn source_target(size: usize) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let _ = stream.write_all(&vec![7u8; size]);
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            });
        }
    });
    port
}

/// Bytes that a seed fixes (xorshift64*), as the relay crate's tests make them.
pub fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// A run of podssh: its exit code, what it wrote, and its words.
pub struct Ran {
    pub code: Option<i32>,
    pub out: Vec<u8>,
    pub err: String,
}

/// `cmd` with `input` on its stdin, then its end; its stdout and stderr
/// read as they come, within [`RUN_LIMIT`].
pub fn run(mut cmd: Command, input: Vec<u8>) -> Ran {
    let mut child =
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let (mut stdout, mut stderr) = (child.stdout.take().expect("stdout"), child.stderr.take().expect("stderr"));
    // Each pipe on a thread of its own: a write that waits must not stop the reads.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let words = std::thread::spawn(move || {
        let mut err = String::new();
        let _ = stderr.read_to_string(&mut err);
        err
    });
    let deadline = Instant::now() + RUN_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let (out, err) = (reader.join().unwrap_or_default(), words.join().unwrap_or_default());
    let Some(status) = status else { panic!("{cmd:?} did not end within {RUN_LIMIT:?}: {err}") };
    Ran { code: status.code(), out, err }
}
