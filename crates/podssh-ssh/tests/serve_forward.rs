//! direct-tcpip into the cage (T-109), with russh's client over a pipe: a
//! forward to an echo listener of the test carries bytes both ways, its
//! EOF reaches the target as a half-close, and the target's end comes back
//! as EOF and then close; a refused dial gets code 2 with its reason in
//! words; a port that is no TCP port, `--no-forwarding` and the bound on
//! open forwards are each refused with their answer. The same against
//! OpenSSH's client: `podssh-cli`'s `tests/serve_forward_openssh.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelId, ChannelMsg, ChannelOpenFailure};
use podssh_ssh::server::{self, Authorized, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// Each refusal of an open that the client was told of: its code and words.
type Refusals = Arc<Mutex<Vec<(u32, String)>>>;

struct Client {
    refusals: Refusals,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_failure(
        &mut self,
        _channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        _language: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refusals.lock().unwrap().push((reason.code(), description.to_string()));
        Ok(())
    }
}

/// A logged-in connection to a new server with `settings`, and the
/// refusals that its client hears.
async fn connect(settings: Settings) -> (client::Handle<Client>, Refusals) {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let refusals = Refusals::default();
    let heard = Client { refusals: refusals.clone() };
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, heard).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    (handle, refusals)
}

/// The `n`th refusal that the client heard, 1 the first: russh's client
/// wakes the opener before it tells its handler, so this waits for it.
async fn nth_refusal(refusals: &Refusals, n: usize) -> (u32, String) {
    let wait = async {
        loop {
            if let Some(heard) = refusals.lock().unwrap().get(n - 1).cloned() {
                return heard;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(LIMIT, wait).await.expect("the client heard the refusal")
}

/// A listener of the test that echoes one connection's bytes until its
/// EOF, then half-closes: the count it echoed, and whether its EOF came.
async fn echo_once() -> (u16, tokio::task::JoinHandle<(usize, bool)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut echoed = 0;
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    tcp.write_all(&buf[..n]).await.unwrap();
                    echoed += n;
                }
                Err(_) => return (echoed, false),
            }
        }
        let _ = tcp.shutdown().await;
        (echoed, true)
    });
    (port, task)
}

/// A port where nothing listens: a listener's, closed.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_carries_bytes_both_ways_and_ends_cleanly() {
    let (handle, _) = connect(Settings::default()).await;
    let (port, echo) = echo_once().await;
    let open = handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1);
    let channel = tokio::time::timeout(LIMIT, open).await.expect("an answer in time").expect("the forward opens");
    let sent: Vec<u8> = (0..1_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let (mut from_far, mut to_far) = tokio::io::split(channel.into_stream());
    let writing = {
        let sent = sent.clone();
        tokio::spawn(async move {
            to_far.write_all(&sent).await.unwrap();
            // The client's EOF: the target's half-close.
            to_far.shutdown().await.unwrap();
        })
    };
    let mut back = Vec::new();
    tokio::time::timeout(LIMIT, from_far.read_to_end(&mut back)).await.expect("the end in time").unwrap();
    writing.await.unwrap();
    assert_eq!(back.len(), sent.len());
    assert!(back == sent, "the bytes came back changed");
    let (echoed, eof) = tokio::time::timeout(LIMIT, echo).await.expect("the target's end").unwrap();
    assert_eq!((echoed, eof), (sent.len(), true), "the target saw each byte and the client's EOF");
}

/// The target ends first: its bytes, then EOF, and the channel stays open
/// for the client's own bytes until the client's EOF; then the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_target_s_end_is_eof_and_the_close_follows_the_client_s() {
    let (handle, _) = connect(Settings::default()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        tcp.write_all(b"banner\n").await.unwrap();
        // Half-closed: the target still reads what comes after its end.
        tcp.shutdown().await.unwrap();
        let mut late = Vec::new();
        let _ = tcp.read_to_end(&mut late).await;
        late
    });
    let mut channel =
        handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1).await.expect("the forward opens");
    let mut order = Vec::new();
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    got.extend_from_slice(&data);
                    order.push("data");
                }
                ChannelMsg::Eof => {
                    order.push("eof");
                    break;
                }
                ChannelMsg::Close => {
                    order.push("close");
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the target's end in time");
    assert_eq!(got, b"banner\n");
    assert_eq!(order.last(), Some(&"eof"), "{order:?}");
    // The other way stays open: the client's bytes reach the target.
    channel.data(&b"after\n"[..]).await.unwrap();
    channel.eof().await.unwrap();
    let late = tokio::time::timeout(LIMIT, target).await.expect("the target's read in time").unwrap();
    assert_eq!(late, b"after\n");
    let closed = tokio::time::timeout(LIMIT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Close) | None => return true,
                Some(ChannelMsg::Data { .. }) => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("the close in time");
    assert!(closed, "no byte after EOF, then the close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_dial_reaches_the_client_with_its_reason() {
    let (handle, refusals) = connect(Settings::default()).await;
    let port = closed_port().await;
    let open = handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1);
    let opened = tokio::time::timeout(LIMIT, open).await.expect("an answer, not a wait");
    assert!(
        matches!(opened, Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed))),
        "code 2: {opened:?}"
    );
    let (code, why) = nth_refusal(&refusals, 1).await;
    assert_eq!(code, 2);
    assert!(why.starts_with("podssh serve: "), "{why}");
    assert!(why.contains(&format!("127.0.0.1:{port}")), "the target in the words: {why}");
    assert!(why.to_lowercase().contains("refused"), "the system's reason in the words: {why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_port_and_a_bad_name_are_refused_with_their_reason() {
    let (handle, refusals) = connect(Settings::default()).await;
    for (n, (host, port, words)) in [
        ("127.0.0.1", 70_000u32, "port 70000 is not a TCP port"),
        ("127.0.0.1", 0, "port 0 is not a TCP port"),
        ("a host", 22, "is not a host name"),
    ]
    .into_iter()
    .enumerate()
    {
        let opened = tokio::time::timeout(LIMIT, handle.channel_open_direct_tcpip(host, port, "127.0.0.1", 1))
            .await
            .expect("an answer, not a wait");
        assert!(opened.is_err(), "{host}:{port}");
        let (code, why) = nth_refusal(&refusals, n + 1).await;
        assert_eq!(code, 2, "{why}");
        assert!(why.contains(words), "{host}:{port}: {why}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_forwarding_refuses_each_forward_and_names_the_flag() {
    let (handle, refusals) = connect(Settings { no_forwarding: true, ..Settings::default() }).await;
    let (port, _echo) = echo_once().await;
    let opened = handle.channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1).await;
    assert!(
        matches!(opened, Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited))),
        "{opened:?}"
    );
    let (code, why) = nth_refusal(&refusals, 1).await;
    assert_eq!(code, 1);
    assert!(why.contains("--no-forwarding"), "{why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_past_the_bound_is_a_resource_shortage_until_one_ends() {
    let (handle, _) = connect(Settings { max_forwards: Some(1), ..Settings::default() }).await;
    let (first_port, _first) = echo_once().await;
    let first = handle.channel_open_direct_tcpip("127.0.0.1", first_port.into(), "127.0.0.1", 1).await.expect("one");
    let (second_port, _second) = echo_once().await;
    let refused = handle.channel_open_direct_tcpip("127.0.0.1", second_port.into(), "127.0.0.1", 1).await;
    assert!(
        matches!(refused, Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage))),
        "{refused:?}"
    );
    // The first ends, and its place comes back.
    first.close().await.unwrap();
    let again = tokio::time::timeout(LIMIT, async {
        loop {
            match handle.channel_open_direct_tcpip("127.0.0.1", second_port.into(), "127.0.0.1", 1).await {
                Ok(channel) => return channel,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("a place again after the first ended");
    drop(again);
}
