//! The GSRN road through podssh's own dial, against a stand-in of the relay
//! on the loopback (T-707): the control messages as gsocket's relay sends
//! them (`LISTEN` and `CONNECT` of 128 bytes, `START` with the side of each
//! end, `ACCEPT`), then the bytes as they come. Two ends of one secret move
//! bytes both ways; two ends of different secrets, which this stand-in pairs
//! anyway as a relay that a defect or a party made careless would, get no
//! connection: TLS with SRP refuses it. The planted defect of the entry's
//! Prove is that second case: a road that let a wrong secret through would
//! pass bytes there.

use std::net::SocketAddr;
use std::time::Duration;

use podssh_gsr::{Role, Settings};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const LISTEN: u8 = 0x01;
const CONNECT: u8 = 0x02;
const START: u8 = 0x05;
const MESSAGE: usize = 32;
const HELLO: usize = 128;
const ADDR_AT: usize = 32;
const WAIT: Duration = Duration::from_secs(20);

struct Hello {
    addr: [u8; 16],
    listener: bool,
    stream: TcpStream,
}

/// The stand-in; `any` pairs a listener with any connector, whatever its
/// address, as a careless relay would.
async fn relay(any: bool) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
    let at = listener.local_addr().expect("its address");
    let (sent, mut came) = mpsc::unbounded_channel::<Hello>();
    let task = tokio::spawn(async move {
        let mut waiting: Vec<Hello> = Vec::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { return };
                    let sent = sent.clone();
                    tokio::spawn(async move {
                        let mut head = [0u8; HELLO];
                        if stream.read_exact(&mut head).await.is_err() || ![LISTEN, CONNECT].contains(&head[0]) {
                            return;
                        }
                        let addr: [u8; 16] = head[ADDR_AT..ADDR_AT + 16].try_into().expect("16 bytes");
                        let _ = sent.send(Hello { addr, listener: head[0] == LISTEN, stream });
                    });
                }
                Some(hello) = came.recv() => {
                    let at = waiting
                        .iter()
                        .position(|other| other.listener != hello.listener && (any || other.addr == hello.addr));
                    match at {
                        Some(at) => {
                            let other = waiting.remove(at);
                            tokio::spawn(carry(other, hello));
                        }
                        None => waiting.push(hello),
                    }
                }
            }
        }
    });
    (at, task)
}

/// Each end's `START` (the listener is the TLS server), its `ACCEPT`, then
/// the bytes.
async fn carry(one: Hello, other: Hello) {
    let (mut server, mut client) = if one.listener { (one.stream, other.stream) } else { (other.stream, one.stream) };
    let mut start = [0u8; MESSAGE];
    start[0] = START;
    start[1] = 0x01;
    if server.write_all(&start).await.is_err() {
        return;
    }
    start[1] = 0x02;
    if client.write_all(&start).await.is_err() {
        return;
    }
    let mut accept = [0u8; MESSAGE];
    if server.read_exact(&mut accept).await.is_err() || client.read_exact(&mut accept).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut server, &mut client).await;
}

fn settings_at(at: SocketAddr) -> Settings {
    let mut settings = podssh_gsr::settings().expect("the data file");
    settings.domain = at.ip().to_string();
    settings.port = at.port();
    settings.sharded = false;
    settings
}

fn listen(settings: &Settings, secret: &'static str) -> JoinHandle<Result<podssh_gsr::Stream, String>> {
    let settings = settings.clone();
    tokio::spawn(async move {
        let dial = podssh_gsr::dialer(&ProxyChoice::Direct);
        podssh_gsr::open(&*dial, &settings, Role::Listen, secret, WAIT).await.map_err(|f| f.chain())
    })
}

async fn connect(settings: &Settings, secret: &str) -> Result<podssh_gsr::Stream, String> {
    let dial = podssh_gsr::dialer(&ProxyChoice::Direct);
    podssh_gsr::open(&*dial, settings, Role::Connect, secret, WAIT).await.map_err(|f| f.chain())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_of_one_secret_move_bytes_both_ways_through_podssh_s_dial() {
    pod_testkit::need_loopback!();
    let (at, relay) = relay(false).await;
    let settings = settings_at(at);
    let listener = listen(&settings, "podssh-gsr-stand-in");
    let mut near = connect(&settings, "podssh-gsr-stand-in").await.expect("the connector");
    let mut far = listener.await.expect("the task").expect("the listener");

    let payload: Vec<u8> = (0u8..=255).cycle().take(256 * 1024).collect();
    let mut got = vec![0u8; payload.len()];
    let (sent, read) = tokio::join!(near.write_all(&payload), far.read_exact(&mut got));
    sent.expect("the bytes");
    read.expect("the bytes arrive");
    assert!(got == payload, "the bytes changed on the way");
    let mut answer = [0u8; 4];
    let (sent, read) = tokio::join!(far.write_all(b"pong"), near.read_exact(&mut answer));
    sent.expect("the answer");
    read.expect("the answer arrives");
    assert_eq!(&answer, b"pong");
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_secret_gives_no_connection_even_where_the_relay_pairs_it() {
    pod_testkit::need_loopback!();
    let (at, relay) = relay(true).await;
    let settings = settings_at(at);
    let listener = listen(&settings, "podssh-gsr-the-node-s");
    let refused = connect(&settings, "podssh-gsr-a-guess").await;
    let why = match refused {
        Ok(_) => panic!("a wrong secret gave a connection"),
        Err(why) => why,
    };
    // The words name neither secret.
    assert!(!why.contains("podssh-gsr-a-guess") && !why.contains("podssh-gsr-the-node-s"), "{why}");
    // The listener's handshake fails too, or it still waits: either way it
    // took no peer.
    if let Ok(joined) = tokio::time::timeout(Duration::from_secs(10), listener).await {
        assert!(joined.expect("the task").is_err(), "the listener took a peer of another secret");
    }
    relay.abort();
}
