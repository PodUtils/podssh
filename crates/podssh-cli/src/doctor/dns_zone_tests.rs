//! The unit tests of `doctor::dns_zone` (T-875): the flags, each verdict
//! from one table, and one query against stand-ins on the loopback, one of
//! which answers another query first.

use super::*;

fn flags(zone: Option<&str>, server: Option<&str>) -> Flags {
    Flags { zone: zone.map(str::to_string), server: server.map(str::to_string) }
}

/// No zone, nothing asked; a zone in lower case with no final dot; a bad
/// zone, a bad resolver and a resolver with no zone are each 64.
#[test]
fn the_flags_name_a_zone_and_a_resolver_or_are_refused() {
    assert_eq!(asked(&flags(None, None)).unwrap(), None);
    let plan = asked(&flags(Some("T.Example.COM."), None)).unwrap().unwrap();
    assert_eq!(plan, Plan { zone: "t.example.com".into(), resolver: Resolver::System });
    let named = asked(&flags(Some("t.example.com"), Some("192.0.2.53"))).unwrap().unwrap();
    assert_eq!(named.resolver, Resolver::Named("192.0.2.53:53".parse().unwrap()));
    let long = format!("{}.example", "a".repeat(64));
    let full = vec!["abcdefghij"; 22].join(".");
    for (zone, server, says) in [
        (Some(""), None, "--dns-zone : give a zone of your own"),
        (Some("."), None, "--dns-zone .: give a zone of your own"),
        (Some("t example"), None, "--dns-zone t example: give a zone"),
        (Some(long.as_str()), None, "give a zone of your own"),
        (Some(full.as_str()), None, "short enough for a label of 23 under it"),
        (Some("t.example\u{1b}[2J"), None, "--dns-zone t.example[2J: give"),
        (Some("t.example"), Some("dns.example"), "--dns-server dns.example is no resolver's address"),
        (None, Some("192.0.2.53"), "--dns-server names the resolver of --dns-zone ZONE"),
    ] {
        let refusal = asked(&flags(zone, server)).unwrap_err();
        assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{zone:?} {server:?}");
        assert!(refusal.message.contains(says), "{zone:?} {server:?}: {}", refusal.message);
        assert!(!refusal.message.contains('\u{1b}'), "{:?}", refusal.message);
    }
}

/// The name of a probe: the prefix, 16 hex digits, the zone.
#[test]
fn a_probe_s_name_is_random_under_the_zone() {
    let name = probe_name("t.example", &[0xab, 1, 2, 3, 4, 5, 6, 7, 99]);
    assert_eq!(name, "podssh-ab01020304050607.t.example");
}

fn facts(rcode: u16, truncated: bool, edns: Option<u16>, others: usize) -> Facts {
    Facts { ms: 41, size: 120, rcode, truncated, edns, txt: 1, others }
}

/// Each verdict from one table: the status, and words that the line holds.
#[test]
fn each_answer_and_each_silence_has_its_own_true_line() {
    let server: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let silent = |ignored: usize| Got::Silent { waited: WAIT, ignored, unreadable: None };
    let answered = |rcode, tc, edns, others| Got::Answered(facts(rcode, tc, edns, others));
    let cases: Vec<(Got, Option<u16>, &str, Vec<&str>)> = vec![
        (
            answered(0, false, Some(1232), 0),
            Some(1232),
            "ok",
            vec![
                "a TXT query with an OPT record of 1232: NOERROR in 41 ms, 120 bytes, TC clear",
                "the OPT record kept (1232), 1 TXT records: the resolver answered it for the zone",
            ],
        ),
        (answered(3, false, None, 0), Some(1232), "ok", vec!["NXDOMAIN", "the OPT record stripped, so answers"]),
        (answered(0, false, None, 0), None, "ok", vec!["with no OPT record: NOERROR", "no OPT record, as asked"]),
        (answered(0, false, Some(4096), 0), None, "ok", vec!["an OPT record of 4096 that the query had not"]),
        (answered(0, true, Some(1232), 0), Some(1232), "ok", vec!["TC set"]),
        (answered(0, false, None, 1), None, "FAIL", vec!["and 1 records of another type", "the road cannot pass here"]),
        (answered(2, false, Some(1232), 0), Some(1232), "FAIL", vec!["SERVFAIL", "check its delegation"]),
        (answered(5, false, Some(1232), 0), Some(1232), "FAIL", vec!["REFUSED", "refuses to ask for this zone"]),
        (answered(16, false, Some(1232), 0), Some(1232), "FAIL", vec!["BADVERS in 41 ms"]),
        (answered(9, false, Some(1232), 0), Some(1232), "FAIL", vec!["RCODE 9 in 41 ms"]),
        (silent(0), Some(1232), "FAIL", vec!["no answer from 192.0.2.53:53 in 3 s: the path or the resolver drops it"]),
        (silent(1), None, "FAIL", vec!["in 3 s (1 datagram that answers another query was not taken)"]),
        (silent(2), None, "FAIL", vec!["(2 datagrams that answer other queries were not taken)"]),
        (
            Got::Silent { waited: WAIT, ignored: 0, unreadable: Some("the answer is for another question".into()) },
            None,
            "FAIL",
            vec!["a TXT query with no OPT record: its answer does not read: the answer is for another question"],
        ),
        (Got::Failed("the query did not go out: EPERM".into()), None, "FAIL", vec!["record: the query did not go"]),
    ];
    for (got, edns, status, words) in cases {
        let verdict = judge(&got, edns, server);
        let (label, detail) = match &verdict {
            Verdict::Ok { detail } => ("ok", detail.clone()),
            Verdict::Failed { detail } => ("FAIL", detail.clone()),
            Verdict::Unknown { why } => ("????", why.clone()),
        };
        assert_eq!(label, status, "{got:?}: {detail}");
        for word in words {
            assert!(detail.contains(word), "{got:?}: {detail:?} lacks {word:?}");
        }
    }
}

/// A stand-in resolver on the loopback, written here from RFC 1035's
/// layout apart from pod-dns: it answers each query once, first with
/// `first` (a datagram of another query, when given), then with its
/// answer: the query's header and question, QR set, one TXT record.
fn stand_in(first: Option<Vec<u8>>) -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buffer) {
            if let Some(other) = &first {
                let _ = socket.send_to(other, from);
            }
            // The query with no OPT record: the header, then the question.
            let mut end = 12;
            while end < n && buffer[end] != 0 {
                end += 1 + usize::from(buffer[end]);
            }
            let end = (end + 5).min(n);
            let mut answer = buffer[..end].to_vec();
            answer[2] |= 0x80;
            answer[3] = 0x80;
            answer[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 2, b'o', b'k']);
            let _ = socket.send_to(&answer, from);
        }
    });
    addr
}

/// One query, read whole, its datagram of another query not taken: the
/// planted defect of the entry (a reader that takes another query's answer
/// as its own) fails here, as the other datagram comes first.
#[tokio::test]
async fn a_query_takes_its_own_answer_and_no_other() {
    let whole = stand_in(None);
    let Got::Answered(facts) = ask(whole, "t.example", Some(EDNS), WAIT).await else { panic!("no answer") };
    assert_eq!((facts.rcode, facts.truncated, facts.edns, facts.txt, facts.others), (0, false, None, 1, 0));
    // Another ID and another name, as a late answer of an earlier query.
    let mut other = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 16, 0, 1];
    other.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 2, b'n', b'o']);
    let after = stand_in(Some(other));
    let Got::Answered(facts) = ask(after, "t.example", None, WAIT).await else { panic!("no answer") };
    assert_eq!((facts.rcode, facts.txt), (0, 1));
    // A silent port: no answer within the wait, nothing else.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let got = ask(silent.local_addr().unwrap(), "t.example", None, Duration::from_millis(300)).await;
    assert_eq!(got, Got::Silent { waited: Duration::from_millis(300), ignored: 0, unreadable: None });
}
