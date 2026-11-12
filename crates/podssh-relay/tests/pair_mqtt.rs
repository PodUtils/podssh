//! The pairing by code through an MQTT broker where no mailbox answers
//! (T-737): Eclipse Mosquitto, software that podssh did not write, with a
//! `websockets` listener on the loopback, as the brokers of `pod-services`
//! serve MQTT over a WebSocket. Two podssh ends whose only mailbox is dead
//! meet at the broker's topic of the code, agree and move each part; a taker
//! of another code reads another topic and finds no giver there. The line of
//! the third party comes before the first broker. Each test says "did not
//! run" with no Mosquitto (`PODSSH_MOSQUITTO_TEST_BIN`), and `mqtt-interop.yml`
//! fails on those words.

#![cfg(all(feature = "pair", feature = "code"))]

mod cleanup;
mod mailbox_harness;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mailbox_harness::nobody_there;
use podssh_relay::code::exchange::{Done, Offer};
use podssh_relay::code::run::{self, Ends, Waits};
use podssh_relay::code::{self, Code};
use podssh_relay::identity::PublicKey;
use podssh_relay::pair::OperatorPart;
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use zeroize::Zeroizing;

const NAME: &str = "0123456789abcdef0123456789abcdef";
// A token of the tests alone, of the form of a pair's.
const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const NODE: PublicKey = PublicKey([0x22; 32]);
const OPERATOR: PublicKey = PublicKey([0x11; 32]);
const LIMIT: Duration = Duration::from_secs(90);

type Said = Arc<Mutex<Vec<String>>>;

/// Mosquitto on a port of the loopback, stopped with its directory when the
/// test ends.
struct Broker {
    child: Child,
    dir: PathBuf,
    url: WsUrl,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn broker(tag: &str) -> Option<Broker> {
    let Some(bin) = std::env::var_os("PODSSH_MOSQUITTO_TEST_BIN") else {
        println!("did not run: PODSSH_MOSQUITTO_TEST_BIN names no mosquitto (mqtt-interop.yml sets it)");
        return None;
    };
    let dir = std::env::temp_dir().join(format!("podssh-mqtt-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let conf = format!("listener {port} 127.0.0.1\nprotocol websockets\nallow_anonymous true\npersistence false\n");
    std::fs::write(dir.join("mosquitto.conf"), conf).unwrap();
    let log = std::fs::File::create(dir.join("mosquitto.log")).unwrap();
    let child = Command::new(bin)
        .arg("-c")
        .arg(dir.join("mosquitto.conf"))
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("mosquitto starts");
    let url = WsUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap();
    let broker = Broker { child, dir, url };
    let until = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "mosquitto did not listen");
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(broker)
}

/// The ends of a pairing whose one mailbox is dead, and the broker after it.
fn ends(broker: &Broker, said: &Said) -> Ends {
    let said = said.clone();
    let say: code::Say = Arc::new(move |line: String| said.lock().unwrap().push(line));
    let mut ends = Ends::new(vec![nobody_there()], code::config(&Trust::Default, &ProxyChoice::Direct, say));
    ends.brokers = vec![code::mqtt::Point { url: broker.url.clone(), login: None }];
    ends
}

fn waits() -> Waits {
    Waits { life: Duration::from_secs(60), giver: Duration::from_secs(5), step: Duration::from_secs(20) }
}

fn offer() -> Offer {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let token = Zeroizing::new(TOKEN.to_string());
    let part = OperatorPart::checked("relay.example.org", NAME.into(), token, now + 3_600_000, now).unwrap();
    Offer { label: "lab".into(), node: NODE, part: Some(part) }
}

/// A code of the same giver's form whose nameplate is another: its topic is
/// another.
fn other(shown: &str) -> String {
    let (nameplate, words) = shown.split_once('-').unwrap();
    let other = (nameplate.parse::<u32>().unwrap() % 9000) + 1000 + 1;
    format!("{other}-{words}")
}

/// The giver and the taker of one code (`typed` from what the giver shows):
/// each one's end, and what the ends said.
async fn pairing(
    broker: &Broker,
    typed: fn(&str) -> String,
    waits: Waits,
) -> (Result<run::Given, code::Failed>, Result<run::Taken, code::Failed>, Said) {
    let said = Said::default();
    let ends = ends(broker, &said);
    let offer = offer();
    let (shown_tx, shown_rx) = tokio::sync::oneshot::channel::<String>();
    let mut shown_tx = Some(shown_tx);
    let mut show = move |made: &Code, _: &str| {
        if let Some(tx) = shown_tx.take() {
            let _ = tx.send(made.for_terminal().to_string());
        }
    };
    let mut admit = |key: &PublicKey| Done { admitted: *key == OPERATOR, said: "the operator of the test".into() };
    let giving = run::give(&ends, &waits, &offer, &mut show, &mut admit);
    let taking = async {
        let shown = shown_rx.await.expect("the giver showed a code");
        let code = Code::parse(&typed(&shown)).expect("a code");
        let mut check = |offer: &Offer| if offer.node == NODE { Ok(()) } else { Err("another node".to_string()) };
        run::take(&ends, &waits, &code, &OPERATOR, &mut check).await
    };
    let (given, taken) =
        tokio::time::timeout(LIMIT, async { tokio::join!(giving, taking) }).await.expect("within the limit");
    (given, taken, said)
}

/// Where no mailbox answers, the two ends meet at the broker, agree, and
/// each moves its part; both name the broker; each says the third party's
/// line before its first broker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_pair_through_the_broker_where_no_mailbox_answers() {
    let Some(broker) = broker("pair") else { return };
    let (given, taken, said) = pairing(&broker, |shown| shown.to_string(), waits()).await;
    let given = given.unwrap_or_else(|f| panic!("the giver: {f}"));
    let taken = taken.unwrap_or_else(|f| panic!("the taker: {f}"));
    assert_eq!(given.operator, OPERATOR);
    assert!(given.done.admitted && taken.done.admitted);
    assert_eq!(taken.offer.node, NODE);
    let port = broker.url.port;
    assert!(
        given.mailbox.contains(&port.to_string()) && taken.mailbox.contains(&port.to_string()),
        "{} {}",
        given.mailbox,
        taken.mailbox
    );
    let lines = said.lock().unwrap().clone();
    let third = lines.iter().filter(|l| l.contains(run::BROKER_WORDS)).count();
    assert!(third >= 2, "each end says the third party's line before its first broker: {lines:?}");
}

/// A taker of another code subscribes to another topic: no giver answers
/// there, and the taker fails; the giver's code lives on, untaken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taker_of_another_code_reads_another_topic_and_finds_no_giver() {
    let Some(broker) = broker("other") else { return };
    // The giver's code lives 15 s here: nobody takes it.
    let (given, taken, _) = pairing(&broker, other, Waits { life: Duration::from_secs(15), ..waits() }).await;
    assert!(taken.is_err(), "a taker of another code met the giver");
    assert!(given.is_err(), "the giver met a taker of another code");
}

/// The live run (T-737, short, Q77 and Q78), asked for with
/// `PODSSH_TEST_MQTT_LIVE=yes` (`mqtt-interop.yml`'s input `live`): two
/// podssh ends whose one mailbox is dead pair through the public brokers of
/// `pod-services`, with their public logins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_two_ends_pair_through_the_public_broker() {
    if std::env::var("PODSSH_TEST_MQTT_LIVE").ok().as_deref() != Some("yes") {
        eprintln!("PODSSH_TEST_MQTT_LIVE is not yes: no live run through a public broker");
        return;
    }
    let said = Said::default();
    let say_to = said.clone();
    let say: code::Say = Arc::new(move |line: String| say_to.lock().unwrap().push(line));
    let mut ends = Ends::new(vec![nobody_there()], code::config(&Trust::Default, &ProxyChoice::FromEnvironment, say));
    ends.brokers = code::brokers(None, None);
    assert!(!ends.brokers.is_empty(), "pod-services lists no mqtt-broker");
    let offer = offer();
    let (shown_tx, shown_rx) = tokio::sync::oneshot::channel::<String>();
    let mut shown_tx = Some(shown_tx);
    let mut show = move |made: &Code, _: &str| {
        if let Some(tx) = shown_tx.take() {
            let _ = tx.send(made.for_terminal().to_string());
        }
    };
    let mut admit = |key: &PublicKey| Done { admitted: *key == OPERATOR, said: "the operator of the test".into() };
    let waits = waits();
    let giving = run::give(&ends, &waits, &offer, &mut show, &mut admit);
    let taking = async {
        let code = Code::parse(&shown_rx.await.expect("a code")).expect("a code");
        let mut check = |offer: &Offer| if offer.node == NODE { Ok(()) } else { Err("another node".to_string()) };
        run::take(&ends, &waits, &code, &OPERATOR, &mut check).await
    };
    let (given, taken) =
        tokio::time::timeout(LIMIT, async { tokio::join!(giving, taking) }).await.expect("within the limit");
    let given = given.unwrap_or_else(|f| panic!("the giver: {f}; {:?}", said.lock().unwrap()));
    let taken = taken.unwrap_or_else(|f| panic!("the taker: {f}"));
    assert!(given.done.admitted && taken.done.admitted);
    eprintln!("paired through {}", given.mailbox);
}
