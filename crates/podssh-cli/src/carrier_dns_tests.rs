//! The unit tests of `carrier_dns` (T-877): FILE's reading from one table
//! of refusals, Q107's bound, and the client's checks before any datagram.

use super::*;

/// A scratch directory of this test, removed at its end.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(tag: &str) -> Dir {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let path = std::env::temp_dir().join(format!("podssh-carrier-dns-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    Dir(path)
}

/// FILE of `text` in `dir`, as `--carrier` names it after `dns:`.
fn file(dir: &Dir, name: &str, text: &str) -> String {
    let path = dir.0.join(name);
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

/// A key as `peer` takes it: 64 hex digits.
const KEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

#[test]
fn a_client_s_file_and_a_node_s_file_read_whole() {
    let d = dir("good");
    let client = file(&d, "client.conf", &format!(
        "# the client\nzone = T.Example.\nresolver = 192.0.2.53:5353\nkey-file = client.key\npeer = {KEY}\n\
         queries-per-second = 10\nin-flight = 4\nquery-timeout = 1.5\npoll-max = 0.5\nanswer = 900\n"
    ));
    let spec = read(&client).unwrap();
    assert_eq!(spec.zone, "t.example");
    assert_eq!(spec.resolver, Resolver::Named("192.0.2.53:5353".parse().unwrap()));
    assert_eq!(spec.key_file, d.0.join("client.key"), "a relative path is read beside FILE");
    assert_eq!(spec.peers.len(), 1);
    let s = spec.settings;
    assert_eq!((s.queries_per_second, s.in_flight, s.answer), (10.0, 4, 900));
    assert_eq!((s.query_timeout, s.poll_max), (Duration::from_millis(1500), Duration::from_millis(500)));
    let text = format!("zone = t.example\nlisten = 0.0.0.0:53\nkey-file = /k\npeer = {KEY}, {KEY}\n");
    let node = file(&d, "node.conf", &text);
    let spec = read(&node).unwrap();
    assert_eq!((spec.resolver, spec.listen), (Resolver::System, Some("0.0.0.0:53".parse().unwrap())));
    assert_eq!(spec.peers.len(), 2);
    assert_eq!(spec.settings, DnsSettings::default(), "pod-link's defaults are within Q107's bound");
    assert!(spec.settings.queries_per_second <= dns_road::MOST_RATE && spec.settings.in_flight <= 8);
}

/// Each refusal of FILE is 78, names FILE, and shows no private byte.
#[test]
fn each_fault_of_the_file_is_78_with_its_own_words() {
    let d = dir("bad");
    let base = format!("zone = t.example\nkey-file = k\npeer = {KEY}\n");
    let long = vec!["abcdefghij"; 22].join(".");
    let cases: Vec<(String, &str)> = vec![
        (format!("{base}queries-per-second = 21\n"), "queries-per-second 21: more than 0 and at most 20 (Q107)"),
        (format!("{base}queries-per-second = 0\n"), "queries-per-second 0: more than 0"),
        (format!("{base}queries-per-second = NaN\n"), "queries-per-second NaN"),
        (format!("{base}in-flight = 9\n"), "in-flight 9: 1 to 8 (Q107)"),
        (format!("{base}in-flight = 0\n"), "in-flight 0: 1 to 8"),
        (format!("{base}answer = 511\n"), "answer 511: 512 to 4096 bytes"),
        (format!("{base}query-timeout = 0\n"), "query-timeout 0: give more than 0"),
        (format!("{base}poll-max = 61\n"), "poll-max 61: give more than 0 and at most 60"),
        (format!("{base}answer = many\n"), "answer many: not a number"),
        (format!("{base}resolver = dns.example\n"), "resolver: dns.example is no resolver's address"),
        (format!("{base}listen = :53\n"), "listen :53: give IP:PORT"),
        (format!("{base}secret = 0011\n"), "secret is no name of the DNS road's file"),
        (format!("{base}zone = again\n"), "zone again"),
        ("key-file = k\npeer = x\n".to_string(), "no zone"),
        (format!("zone = {long}\nkey-file = k\npeer = {KEY}\n"), "zone: "),
        (format!("zone = t example\nkey-file = k\npeer = {KEY}\n"), "zone: "),
        (format!("zone = t.example\npeer = {KEY}\n"), "no key-file"),
        ("zone = t.example\nkey-file = k\n".to_string(), "no peer"),
        ("zone = t.example\nkey-file = k\npeer = nokey\n".to_string(), "peer: its key 1 is no key or fingerprint"),
        ("zone = t.example\nkey-file = k\njust words\n".to_string(), "line 3: not NAME = VALUE"),
    ];
    for (text, says) in cases {
        let path = file(&d, "bad.conf", &text);
        let refusal = read(&path).unwrap_err();
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG, "{text:?}: {}", refusal.message);
        assert!(refusal.message.starts_with(&format!("--carrier dns:{path}: ")), "{}", refusal.message);
        assert!(refusal.message.contains(says), "{text:?}: {:?} lacks {says:?}", refusal.message);
        assert!(!refusal.message.contains("0011"), "{}", refusal.message);
    }
    let not_text = d.0.join("binary.conf");
    std::fs::write(&not_text, [0xff, 0xfe, b'\n']).unwrap();
    assert!(read(&not_text.display().to_string()).unwrap_err().message.contains("not UTF-8 text"));
    let missing = d.0.join("none.conf").display().to_string();
    assert_eq!(read(&missing).unwrap_err().code, crate::exitmap::sysexits::EX_CONFIG);
}

/// A client pins one key, and its probe of UDP toward the loopback opens
/// with nothing sent.
#[test]
fn a_client_pins_one_key_and_probes_udp_first() {
    let d = dir("client");
    let text = format!("zone = t.example\nresolver = 127.0.0.1:53\nkey-file = k\npeer = {KEY} {KEY}\n");
    let two = file(&d, "two.conf", &text);
    let refusal = client_ready(&read(&two).unwrap()).unwrap_err();
    assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG);
    assert!(refusal.message.contains("one key on a client's side"), "{}", refusal.message);
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    silent.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let at = silent.local_addr().unwrap();
    let one = file(&d, "one.conf", &format!("zone = t.example\nresolver = {at}\nkey-file = k\npeer = {KEY}\n"));
    let (server, _) = client_ready(&read(&one).unwrap()).expect("UDP on the loopback");
    assert_eq!(server, at);
    assert!(silent.recv_from(&mut [0u8; 1]).is_err(), "the probe sent a datagram");
}

/// This end's key is made once, private, and read the next time.
#[test]
fn this_end_s_key_is_made_once_then_read() {
    let d = dir("key");
    let conf = file(&d, "c.conf", &format!("zone = t.example\nkey-file = mine.key\npeer = {KEY}\n"));
    let spec = read(&conf).unwrap();
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = lines.clone();
    let say: podssh_relay::filehost::Say = Arc::new(move |line: String| kept.lock().unwrap().push(line));
    let first = key_of(&spec, &say).unwrap().public();
    let second = key_of(&spec, &say).unwrap().public();
    assert_eq!(first, second, "the second run reads the key that the first made");
    let said = lines.lock().unwrap().clone();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains(&format!("give {first} to the other end's peer")), "{said:?}");
}
