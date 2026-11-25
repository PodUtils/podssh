//! The unit tests of `carrier_dns` (T-877): FILE's reading from one table
//! of refusals, Q107's bound, and the client's checks before any datagram.

use std::path::PathBuf;

use pod_link::dns::DnsSettings;

use super::spec_file::{for_side, zone_of};
use super::*;
use crate::dns_road::Resolver;

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
    // Others may not change FILE: an umask of 002 would make it 664.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.display().to_string()
}

/// A key as `peer` takes it: 64 hex digits.
const KEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

#[test]
fn a_client_s_file_and_a_node_s_file_read_whole() {
    let d = dir("good");
    let client = file(
        &d,
        "client.conf",
        &format!(
            "# the client\nzone = T.Example.\nresolver = 192.0.2.53:5353\nkey-file = client.key\npeer = {KEY}\n\
         queries-per-second = 10\nin-flight = 4\nquery-timeout = 0.8\npoll-max = 0.5\nanswer = 900\n"
        ),
    );
    let spec = read(&client).unwrap();
    assert_eq!(spec.zone, "t.example");
    assert_eq!(spec.resolver, Resolver::Named("192.0.2.53:5353".parse().unwrap()));
    assert_eq!(spec.key_file, d.0.join("client.key"), "a relative path is read beside FILE");
    assert_eq!(spec.peers.len(), 1);
    let s = spec.settings;
    assert_eq!((s.queries_per_second, s.in_flight, s.answer), (10.0, 4, 900));
    assert_eq!((s.query_timeout, s.poll_max), (Duration::from_millis(800), Duration::from_millis(500)));
    assert!(s.hold < s.query_timeout, "a short query-timeout lowers pod-link's held poll: {s:?}");
    for (text, quiet) in [("poll-max = 0.5\n", 5), ("poll-max = 30\n", 31)] {
        let f = file(
            &d,
            "quiet.conf",
            &format!("zone = t.example\nlisten = 0.0.0.0:53\nkey-file = /k\npeer = {KEY}\n{text}"),
        );
        let spec = read(&f).unwrap();
        let identity = Identity::from_seed(&[7; 32]);
        let quiet_of = carrier(&spec, identity).handshake_quiet;
        assert_eq!(quiet_of, Duration::from_secs(quiet), "a node waits past its poll-max: {text}");
    }
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
        (format!("{base}queries-per-second = 21\n"), "queries-per-second 21: give more than 0 and at most 20"),
        (format!("{base}queries-per-second = 0\n"), "queries-per-second 0: give more than 0"),
        (format!("{base}queries-per-second = NaN\n"), "queries-per-second NaN"),
        (format!("{base}in-flight = 9\n"), "in-flight 9: give 1 to 8"),
        (format!("{base}in-flight = 0\n"), "in-flight 0: give 1 to 8"),
        (format!("{base}in-flight = 99999999999999999999\n"), "in-flight 99999999999999999999: give 1 to 8"),
        (format!("{base}in-flight = 2.5\n"), "in-flight 2.5: not a whole number"),
        (format!("{base}answer = 511\n"), "answer 511: give 512 to 4096 bytes"),
        (format!("{base}query-timeout = 0\n"), "query-timeout 0: give more than 0"),
        (format!("{base}query-timeout = 61\n"), "query-timeout 61: give more than 0 and at most 60 seconds"),
        (format!("{base}poll-max = 61\n"), "poll-max 61: give more than 0 and at most 60"),
        // The user's own text, not the number that it parses to.
        (
            format!("{base}poll-max = 99999999999999999999\n"),
            "poll-max 99999999999999999999: give more than 0 and at most 60 seconds",
        ),
        (format!("{base}answer = many\n"), "answer many: not a whole number"),
        (format!("{base}resolver = dns.example\n"), "resolver: dns.example is no resolver's address"),
        (format!("{base}resolver = https://dns.example\n"), "the path is missing"),
        (format!("{base}resolver = https://dns.example/\n"), "the path is missing"),
        (format!("{base}listen = :53\n"), "listen :53: give IP:PORT"),
        (format!("{base}secret = 0011\n"), "line 4: secret is no name of the DNS road's file"),
        (format!("{base}zone = again\n"), "line 4: zone is given twice (lines 1 and 4)"),
        (format!("{base}= alone\n"), "line 4: no name before ="),
        (format!("{base}answer = 900 # bytes\n"), "line 4: answer: a comment takes a line of its own"),
        (format!("zone = t.example\nkey-file = k\npeer = {KEY} # the node\n"), "line 3: peer: a comment"),
        ("key-file = k\npeer = x\n".to_string(), "no zone"),
        (format!("zone = {long}\nkey-file = k\npeer = {KEY}\n"), "too long to leave room"),
        (format!("zone = t example\nkey-file = k\npeer = {KEY}\n"), "zone t example: give letters, digits"),
        (format!("zone = t\0x.example\nkey-file = k\npeer = {KEY}\n"), "zone t\\u{0}x.example: give letters"),
        (format!("zone = a\nkey-file = k\npeer = {KEY}\n"), "zone a: one label"),
        (format!("zone = -a.example\nkey-file = k\npeer = {KEY}\n"), "starts or ends with -"),
        (format!("zone = a-.example\nkey-file = k\npeer = {KEY}\n"), "starts or ends with -"),
        (format!("zone = a..example\nkey-file = k\npeer = {KEY}\n"), "an empty label"),
        (format!("zone = .a.example\nkey-file = k\npeer = {KEY}\n"), "an empty label"),
        (format!("zone = t.example\npeer = {KEY}\n"), "no key-file: give the path of this end's key"),
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
    let not_text = file(&d, "binary.conf", "");
    std::fs::write(&not_text, [0xff, 0xfe, b'\n']).unwrap();
    assert!(read(&not_text).unwrap_err().message.contains("not UTF-8 text"));
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

/// What a person's editor or hand leaves is read, not refused: a BOM first,
/// CRLF ends, a comment line, and a fraction of queries a second.
#[test]
fn a_bom_crlf_and_a_fraction_are_read() {
    let d = dir("lenient");
    let text = format!(
        "\u{feff}# the client\r\nzone = t.example\r\nkey-file = k\r\npeer = {KEY}\r\nqueries-per-second = 1.5\r\n"
    );
    let spec = read(&file(&d, "bom.conf", &text)).unwrap();
    assert_eq!((spec.zone.as_str(), spec.settings.queries_per_second), ("t.example", 1.5));
    for (zone, want) in [("T.Example.", "t.example"), ("_dns.a-b.example", "_dns.a-b.example")] {
        assert_eq!(zone_of(zone).as_deref(), Ok(want), "{zone}");
    }
}

/// A key pasted as key-file is refused, and never shown: it would else name
/// a new key file. A file of that name is a path, and is taken.
#[test]
fn a_pasted_key_as_key_file_is_78_and_not_shown() {
    let d = dir("pasted");
    let text = format!("zone = t.example\nkey-file = {KEY}\npeer = {KEY}\n");
    let refusal = read(&file(&d, "p.conf", &text)).unwrap_err();
    assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG);
    let says = "line 2: key-file is the path of this end's key file, not a key";
    assert!(refusal.message.contains(says), "{}", refusal.message);
    assert!(!refusal.message.contains(KEY), "the pasted key is shown: {}", refusal.message);
    assert!(!d.0.join(KEY).exists(), "a key file was made under the pasted key's name");
    std::fs::write(d.0.join(KEY), "").unwrap();
    let conf = file(&d, "q.conf", &text);
    assert_eq!(read(&conf).unwrap().key_file, d.0.join(KEY), "an existing file of that name is a path");
}

/// The other end's setting is refused at each end (78), with its line.
#[test]
fn a_setting_of_the_other_end_is_78() {
    let d = dir("side");
    let client = file(&d, "c.conf", &format!("zone = t.example\nkey-file = k\npeer = {KEY}\nlisten = 0.0.0.0:53\n"));
    let node = file(&d, "n.conf", &format!("zone = t.example\nkey-file = k\npeer = {KEY}\nresolver = system\n"));
    let cases = [
        (client.as_str(), Side::Client, "line 4: listen is the node's setting, which a client's file does not take"),
        (node.as_str(), Side::Node, "line 4: resolver is the client's setting, which a node's file does not take"),
    ];
    for (conf, side, says) in cases {
        let spec = read(conf).unwrap();
        let refusal = for_side(&spec, side).unwrap_err();
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG, "{says}");
        assert!(refusal.message.contains(says), "{}", refusal.message);
        let other = if side == Side::Client { Side::Node } else { Side::Client };
        assert!(for_side(&spec, other).is_ok(), "{says}: its own end takes it");
    }
    assert!(client_peer(&read(&client).unwrap()).is_err(), "a client checks its file before anything");
}

/// FILE lists the node's allowlist: one that others can change is refused
/// (78), as the settings file is; the owner's alone is read.
#[cfg(unix)]
#[test]
fn a_file_that_others_can_change_is_78() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("mode");
    let conf = file(&d, "m.conf", &format!("zone = t.example\nkey-file = k\npeer = {KEY}\n"));
    for (mode, refused) in [(0o666, true), (0o664, true), (0o646, true), (0o644, false), (0o600, false)] {
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(mode)).unwrap();
        match (read(&conf), refused) {
            (Err(refusal), true) => {
                assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG, "{mode:o}");
                assert!(refusal.message.contains("no one else may change it"), "{mode:o}: {}", refusal.message);
            }
            (Ok(_), false) => {}
            (got, _) => panic!("mode {mode:o}: {got:?}"),
        }
    }
}

/// A failed bind of `listen` is mapped as pipe's listeners map theirs.
#[test]
fn a_refused_bind_is_77_and_another_failure_69() {
    use std::io::ErrorKind;
    let cases = [
        (CarrierErrorKind::Refused, 77),
        (CarrierErrorKind::Io(ErrorKind::PermissionDenied), 77),
        (CarrierErrorKind::InUse, 69),
        (CarrierErrorKind::Io(ErrorKind::AddrNotAvailable), 69),
        (CarrierErrorKind::Usage, 69),
    ];
    for (kind, code) in cases {
        assert_eq!(bind_code(kind), code, "{kind:?}");
    }
}

/// A port in use is 69 at the bind, which comes before the node says that
/// it serves. Windows may give another error for a second bind.
#[cfg(unix)]
#[test]
fn a_listen_in_use_is_69_at_the_bind() {
    let d = dir("inuse");
    let held = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let at = held.local_addr().unwrap();
    let conf = file(&d, "n.conf", &format!("zone = t.example\nlisten = {at}\nkey-file = k\npeer = {KEY}\n"));
    let spec = read(&conf).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let refusal = match runtime.block_on(bind(&spec)) {
        Ok(_) => panic!("{at} is in use, yet the node bound it"),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.code, 69, "{}", refusal.message);
    assert!(refusal.message.contains(&format!("cannot listen on {at} (UDP)")), "{}", refusal.message);
}
