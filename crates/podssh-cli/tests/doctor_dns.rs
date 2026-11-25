//! `podssh doctor --dns-zone ZONE --dns-server ADDR` (T-875) as a process:
//! offline, one `????` and nothing sent; a bad flag, 64 before any probe;
//! and, through a stand-in proxy on the loopback that refuses each CONNECT,
//! the section dns against stand-in resolvers on the loopback, one for each
//! class of answer (whole, the OPT record stripped, cut, an address, SERVFAIL,
//! another query's answer then silence), and against pod-link's own
//! responder. Each gives its own true line. The stand-ins are written here
//! from RFC 1035's layout, apart from pod-dns, which podssh reads with. No
//! datagram and no connection leaves the loopback; the system resolver is
//! asked for the relay's name, as in the other tests of doctor.

mod cleanup;

use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(120);
/// The zone of each run.
const ZONE: &str = "t.example";

/// Every variable that could steer the doctor somewhere this test did not
/// choose; the test sets the ones that it uses.
const STEERING: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "PODSSH_OFFLINE",
    "PODSSH_RELAY",
    "PODSSH_RELAY_ADDR",
    "PODSSH_RELAY_TOKEN",
    "PODSSH_FORWARDER",
    "PODSSH_VIA",
    "PODSSH_IROH_RELAY",
    "PODSSH_STUN",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

/// One doctor at a time, as the other tests of doctor run.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn scratch() -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-dns-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// `podssh doctor ARGS` with `set`, HOME and the cache in a scratch
/// directory and no settings file.
fn doctor(args: &[&str], set: &[(&str, &str)]) -> Run {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_CACHE_DIR", home.join("cache")).env("PODSSH_SETTINGS", "none");
    for (name, value) in set {
        cmd.env(name, value);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || std::io::read_to_string(&mut out).unwrap_or_default());
    let err = std::thread::spawn(move || std::io::read_to_string(&mut err).unwrap_or_default());
    let began = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if began.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh doctor {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run { code: status.code().unwrap_or(-1), out: out.join().unwrap(), err: err.join().unwrap() }
}

/// The item `check` of a report of `--json`: its section, status and detail.
fn item(out: &str, check: &str) -> Option<(String, String, String)> {
    let doc: serde_json::Value = serde_json::from_str(out).unwrap_or_else(|e| panic!("{e}: {out}"));
    let item = doc["checks"].as_array().unwrap().iter().find(|c| c["check"] == check)?.clone();
    let text = |key: &str| item[key].as_str().unwrap_or_default().to_string();
    Some((text("section"), text("status"), text("detail")))
}

/// Offline: one `????`, nothing sent, and no line of a query.
#[test]
fn offline_the_section_is_one_unknown_and_nothing_is_sent() {
    let run = doctor(&["--json", "--quick", "--dns-zone", ZONE], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    let (_, status, detail) = item(&run.out, "dns resolver").expect("a line dns resolver");
    assert_eq!((status.as_str(), detail.as_str()), ("unknown", "not attempted: PODSSH_OFFLINE is set"));
    assert_eq!(item(&run.out, "dns edns0"), None, "{}", run.out);
    // Without the zone, no line of the section at all.
    let none = doctor(&["--json", "--quick"], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(item(&none.out, "dns resolver"), None, "{}", none.out);
}

/// A bad flag is 64 before any probe, with nothing on stdout.
#[test]
fn a_bad_flag_is_64_before_any_probe() {
    for (args, says) in [
        (vec!["--dns-server", "127.0.0.1"], "--dns-server names the resolver of --dns-zone ZONE"),
        (vec!["--dns-zone", "t example"], "--dns-zone t example: give a zone of your own"),
        (vec!["--dns-zone", ZONE, "--dns-server", "dns.example"], "dns.example is no resolver's address"),
    ] {
        let run = doctor(&args, &[("PODSSH_OFFLINE", "1")]);
        assert_eq!(run.code, 64, "{args:?}: {}{}", run.out, run.err);
        assert!(run.out.is_empty(), "{args:?}: {}", run.out);
        assert!(run.err.contains(says), "{args:?}: {}", run.err);
    }
}

/// A stand-in proxy that refuses each CONNECT at once, so that the other
/// sections end quickly and nothing leaves the loopback.
fn refusing_proxy() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
                while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = conn.write_all(b"HTTP/1.1 403 refused by the stand-in\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    port
}

/// What a stand-in resolver does with each query.
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// One TXT record, and the OPT record when the query had one.
    Whole,
    /// One TXT record and never an OPT record: a resolver that strips it.
    Stripped,
    /// The TC bit and no record.
    Cut,
    /// An A record of 192.0.2.1: a portal that answers each name itself.
    Portal,
    /// SERVFAIL and no record.
    Servfail,
    /// A datagram of another query, then nothing.
    Other,
}

/// The end of the question of the query `msg` of `n` bytes.
fn question_end(msg: &[u8], n: usize) -> usize {
    let mut at = 12;
    while at < n && msg[at] != 0 {
        at += 1 + usize::from(msg[at]);
    }
    (at + 5).min(n)
}

/// A stand-in resolver on the loopback.
fn resolver(mode: Mode) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buffer) {
            if n < 12 {
                continue;
            }
            let had_opt = buffer[11] == 1;
            let end = question_end(&buffer, n);
            // The header and the question, QR and RA set, RCODE 0, no record.
            let mut answer = buffer[..end].to_vec();
            answer[2] |= 0x80;
            answer[3] = 0x80;
            answer[6..12].fill(0);
            let txt = [0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 2, b'o', b'k'];
            let opt = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];
            match mode {
                Mode::Whole | Mode::Stripped => {
                    answer[7] = 1;
                    answer.extend_from_slice(&txt);
                    if had_opt && matches!(mode, Mode::Whole) {
                        answer[11] = 1;
                        answer.extend_from_slice(&opt);
                    }
                }
                Mode::Cut => answer[2] |= 0x02,
                Mode::Portal => {
                    answer[7] = 1;
                    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
                }
                Mode::Servfail => answer[3] = 0x82,
                Mode::Other => {
                    // Another ID and another name: an earlier query's answer.
                    let mut other = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 16, 0, 1];
                    other.extend_from_slice(&txt);
                    let _ = socket.send_to(&other, from);
                    continue;
                }
            }
            let _ = socket.send_to(&answer, from);
        }
    });
    addr
}

/// pod-link's own responder for ZONE on the loopback (PodUtils/podcrates,
/// feature `dns`), with a key made for the test.
fn pod_link_responder() -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let provider = podssh_ws::tls::context().provider().clone();
            let identity = Arc::new(podssh_relay::identity::Identity::from_seed(&[7; 32]));
            let dns = pod_link::dns::Dns::new(provider, identity).zone(ZONE);
            let listener = dns.bind("127.0.0.1:0".parse().unwrap()).await.expect("the responder binds");
            tx.send(listener.local_addr()).unwrap();
            // The listener lives as long as the test's process.
            std::future::pending::<()>().await;
        });
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("the responder's address")
}

/// The lines of the section through the stand-in proxy, against `server`:
/// the resolver's, then each query's, as (status, detail).
fn section(server: SocketAddr) -> [(String, String); 3] {
    let proxy = format!("http://127.0.0.1:{}", refusing_proxy());
    let server = server.to_string();
    let args = ["--json", "--quick", "--relay-host", "relay.test", "--dns-zone", ZONE, "--dns-server", &server];
    let run = doctor(&args, &[("https_proxy", proxy.as_str())]);
    ["dns resolver", "dns edns0", "dns no edns0"].map(|check| {
        let (section, status, detail) =
            item(&run.out, check).unwrap_or_else(|| panic!("no line {check}: {}{}", run.out, run.err));
        assert_eq!(section, "dns", "{check}: {detail}");
        (status, detail)
    })
}

/// Each class of answer gives its own line; the resolver's line is ok, as
/// UDP opens on the loopback.
#[test]
fn against_stand_ins_each_answer_has_its_own_true_line() {
    type Want = (&'static str, &'static str);
    let cases: [(Mode, Want, Want); 6] = [
        (Mode::Whole, ("ok", "NOERROR"), ("ok", "no OPT record, as asked")),
        (Mode::Stripped, ("ok", "the OPT record stripped, so answers keep to 512 bytes"), ("ok", "NOERROR")),
        (Mode::Cut, ("ok", "TC set"), ("ok", "TC set")),
        (Mode::Portal, ("FAIL", "records of another type"), ("FAIL", "a portal that answers each name itself")),
        (Mode::Servfail, ("FAIL", "SERVFAIL"), ("FAIL", "check its delegation")),
        (Mode::Other, ("FAIL", "(1 datagram that answers another query was not taken)"), ("FAIL", "no answer")),
    ];
    for (mode, edns, plain) in cases {
        let server = resolver(mode);
        let [resolver_line, edns_line, plain_line] = section(server);
        assert_eq!(resolver_line.0, "ok", "{mode:?}: {}", resolver_line.1);
        assert!(resolver_line.1.starts_with(&format!("{server}, from --dns-server")), "{}", resolver_line.1);
        for (line, (status, words)) in [(&edns_line, edns), (&plain_line, plain)] {
            assert_eq!(line.0, status, "{mode:?}: {}", line.1);
            assert!(line.1.contains(words), "{mode:?}: {:?} lacks {words:?}", line.1);
        }
        assert!(edns_line.1.starts_with("a TXT query with an OPT record of 1232: "), "{}", edns_line.1);
        assert!(plain_line.1.starts_with("a TXT query with no OPT record: "), "{}", plain_line.1);
    }
    let whole = section(resolver(Mode::Whole));
    assert!(whole[1].1.contains("the OPT record kept (1232), 1 TXT records"), "{}", whole[1].1);
}

/// pod-link's responder answers a name that is no datagram of its own with
/// an empty NOERROR (podcrates `v0.83.0`, T-876 finding 1), so the probe's
/// random name is ok against the node of the DNS road itself.
#[test]
fn pod_link_s_responder_answers_a_random_name_with_an_empty_noerror() {
    let [resolver_line, edns_line, plain_line] = section(pod_link_responder());
    assert_eq!(resolver_line.0, "ok", "{}", resolver_line.1);
    for line in [edns_line, plain_line] {
        assert_eq!(line.0, "ok", "{}", line.1);
        assert!(line.1.contains(": NOERROR in "), "{}", line.1);
        assert!(line.1.contains("0 TXT records"), "{}", line.1);
    }
}
