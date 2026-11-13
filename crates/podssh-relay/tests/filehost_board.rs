//! The board of the file hosts' road (T-738) against Eclipse Mosquitto,
//! software that podssh did not write, with a `websockets` listener on the
//! loopback, as the brokers of `pod-services` serve MQTT over a WebSocket: a
//! note put at a topic is taken by a later connection, a cleared topic keeps
//! none, and a topic of no note is none within the take's short wait. Then a
//! piece goes through the carrier with this board and a stand-in host. Each
//! test says "did not run" with no Mosquitto (`PODSSH_MOSQUITTO_TEST_BIN`),
//! and `mqtt-interop.yml` fails on those words.

#![cfg(feature = "filehost")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::code;
use podssh_relay::filehost::keys::{Keys, LinkId, Way};
use podssh_relay::filehost::mqtt::MqttBoard;
use podssh_relay::filehost::Board;
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};

// A token of the tests alone, of the form of a pair's.
const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";

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
    let dir = std::env::temp_dir().join(format!("podssh-filehost-mqtt-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A free port: bound here, let go, then Mosquitto's.
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

fn board(broker: &Broker) -> MqttBoard {
    let say: code::Say = Arc::new(|_| {});
    let config = code::config(&Trust::Default, &ProxyChoice::Direct, say);
    MqttBoard::new(code::mqtt::Point { url: broker.url.clone(), login: None }, config)
}

#[tokio::test]
async fn a_note_is_kept_for_a_later_connection_and_a_clear_leaves_none() {
    let Some(broker) = broker("note") else { return };
    let board = board(&broker);
    let keys = Keys::from_bytes([4; 32]);
    let topic = keys.topic(Way::Up, &LinkId([2; 16]), 0);
    assert_eq!(board.take(&topic).await.unwrap(), None, "no note yet");
    board.put(&topic, b"sealed note".to_vec()).await.unwrap();
    assert_eq!(board.take(&topic).await.unwrap().as_deref(), Some(&b"sealed note"[..]), "kept for a later take");
    assert_eq!(board.take(&topic).await.unwrap().as_deref(), Some(&b"sealed note"[..]), "a take clears nothing");
    board.put(&topic, b"the next".to_vec()).await.unwrap();
    assert_eq!(board.take(&topic).await.unwrap().as_deref(), Some(&b"the next"[..]), "in the place of the one before");
    board.clear(&topic).await.unwrap();
    assert_eq!(board.take(&topic).await.unwrap(), None, "cleared");
    let door = keys.door();
    board.put(&door, vec![7; 60_000]).await.unwrap();
    assert_eq!(board.take(&door).await.unwrap().map(|n| n.len()), Some(60_000), "a note near the most");
    board.clear(&door).await.unwrap();
}

/// A link of the road between a client and a node over Mosquitto and a
/// host that each holds in memory: the hello, then 64 KiB each way.
#[tokio::test]
async fn a_client_and_a_node_meet_and_move_bytes_through_the_broker() {
    use podssh_relay::filehost::pace::Gate;
    use podssh_relay::filehost::{link, Carrier, Host, Say};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(broker) = broker("link") else { return };
    let host: Arc<dyn Host> = Arc::new(memory::Memory::default());
    let say: Say = Arc::new(|_| {});
    let keys = Arc::new(Keys::of_pair("filehost-pair", TOKEN));
    let carrier = |board: MqttBoard| {
        let board: Arc<dyn Board> = Arc::new(board);
        Arc::new(Carrier::new(keys.clone(), vec![host.clone()], board, Gate::default(), say.clone()))
    };
    let (client, node) = (carrier(board(&broker)), carrier(board(&broker)));
    let accepting = tokio::spawn(link::accept(node));
    let mut at_client = link::dial(client).await.unwrap();
    let mut at_node = tokio::time::timeout(Duration::from_secs(180), accepting).await.unwrap().unwrap().unwrap();
    let (up, down): (Vec<u8>, Vec<u8>) = ((0..65_536).map(|i| i as u8).collect(), vec![9; 65_536]);
    let moving = async {
        let (a, b) = tokio::join!(
            async {
                at_client.write_all(&up).await.unwrap();
                at_client.shutdown().await.unwrap();
                let mut got = Vec::new();
                at_client.read_to_end(&mut got).await.unwrap();
                got
            },
            async {
                at_node.write_all(&down).await.unwrap();
                at_node.shutdown().await.unwrap();
                let mut got = Vec::new();
                at_node.read_to_end(&mut got).await.unwrap();
                got
            }
        );
        (a, b)
    };
    let (at_c, at_n) = tokio::time::timeout(Duration::from_secs(600), moving).await.expect("within 10 minutes");
    assert_eq!((at_c, at_n), (down, up));
}

/// A host in memory, for the test of the board alone.
mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use podssh_relay::filehost::host::{Doing, Host, Stored};

    #[derive(Default)]
    pub struct Memory {
        files: Mutex<(u64, HashMap<String, Vec<u8>>)>,
    }

    impl Host for Memory {
        fn name(&self) -> &str {
            "memory.stand-in.test"
        }
        fn most(&self) -> usize {
            8 << 20
        }
        fn per_hour(&self) -> Option<u32> {
            Some(100_000)
        }
        fn one_person(&self) -> bool {
            false
        }
        fn owns(&self, url: &str) -> bool {
            url.starts_with("https://memory.stand-in.test/")
        }
        fn upload(&self, sealed: Vec<u8>) -> Doing<'_, Stored> {
            let mut files = self.files.lock().unwrap();
            files.0 += 1;
            let url = format!("https://memory.stand-in.test/{}", files.0);
            files.1.insert(url.clone(), sealed);
            Box::pin(async move { Ok(Stored { url, token: None }) })
        }
        fn fetch<'a>(&'a self, url: &'a str, _: usize) -> Doing<'a, Vec<u8>> {
            let found = self.files.lock().unwrap().1.get(url).cloned();
            Box::pin(async move { found.ok_or_else(|| podssh_relay::filehost::Refusal::Failed("404".into())) })
        }
        fn delete<'a>(&'a self, _: &'a Stored) -> Doing<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }
}
