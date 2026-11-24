//! A stock client's `-R` through `podssh serve` (T-123), against a stand-in
//! of the relay in memory: russh's client asks `tcpip-forward` for port 0
//! and is told the port that the stand-in published; a session on the
//! published name opens a `forwarded-tcpip` channel to the client, toward
//! the address and port of the request, and bytes go both ways; a cancel
//! stops the forward once, and the connection's end stops the rest. With no
//! publisher, or with `--no-forwarding`, each request is refused, and serve
//! binds nothing either way: the stand-in is the only way out.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, Channel};
use podssh_ssh::server::remote_forward::{Asked, Opener, Publish, Published, Publisher, Publishing, Stop};
use podssh_ssh::server::{self, Authorized, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);
/// The port that the stand-in gives a request of port 0.
const GIVEN: u32 = 40_022;

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

/// The stand-in of the relay: each forward published, its opener, and the
/// names whose teardown ran.
#[derive(Clone, Default)]
struct StandIn {
    asked: Arc<Mutex<Vec<(Asked, Opener)>>>,
    stopped: Arc<Mutex<Vec<String>>>,
}

impl Publish for StandIn {
    fn publish(&self, asked: Asked, opener: Opener) -> Publishing {
        let port = if asked.port == 0 { GIVEN } else { asked.port };
        let name = format!("p-{}-{port}", asked.address);
        self.asked.lock().unwrap().push((asked, opener));
        let (stopped, gone) = (self.stopped.clone(), name.clone());
        let stop = Stop::new(move || stopped.lock().unwrap().push(gone));
        Box::pin(async move { Ok(Published { name, port, stop }) })
    }
}

/// The client: it trusts the host key, and keeps each forwarded channel
/// with the address and port that it names.
#[derive(Clone, Default)]
struct Client {
    channels: Arc<Mutex<Vec<(Channel<client::Msg>, String, u32)>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().unwrap().push((channel, connected_address.to_string(), connected_port));
        reply.accept().await;
        Ok(())
    }
}

/// A logged-in client of a server with `settings`, and the server's task.
async fn logged_in(settings: Settings, seen: Client) -> (client::Handle<Client>, tokio::task::JoinHandle<()>) {
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let (near, far) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let _ = server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)).await;
    });
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, seen).await.expect("handshake");
    let auth = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", auth).await.expect("an answer").success());
    (handle, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_is_published_and_its_sessions_reach_the_client() {
    let stand_in = StandIn::default();
    let settings = Settings { remote: Some(Publisher(Arc::new(stand_in.clone()))), ..Settings::default() };
    let seen = Client::default();
    let (handle, server) = tokio::time::timeout(LIMIT, logged_in(settings, seen.clone())).await.expect("in time");
    let port = tokio::time::timeout(LIMIT, handle.tcpip_forward("127.0.0.1", 0)).await.expect("in time");
    assert_eq!(port.expect("granted"), GIVEN, "a request of port 0 is told the published port");
    let second = tokio::time::timeout(LIMIT, handle.tcpip_forward("localhost", 2201)).await.expect("in time");
    assert_eq!(second.expect("granted"), 2201);
    let opener = {
        let asked = stand_in.asked.lock().unwrap();
        assert_eq!(asked.len(), 2);
        assert_eq!((asked[0].0.address.as_str(), asked[0].0.port), ("127.0.0.1", 0));
        asked[1].1.clone()
    };
    // A session on the second name: the channel names its request.
    let opened = tokio::time::timeout(LIMIT, opener.open("192.0.2.7", 50_000)).await.expect("in time");
    let mut far = opened.expect("opened");
    let (channel, address, port) = tokio::time::timeout(LIMIT, async {
        loop {
            if let Some(one) = seen.channels.lock().unwrap().pop() {
                return one;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the client's channel");
    assert_eq!((address.as_str(), port), ("localhost", 2201));
    let mut near = channel.into_stream();
    far.write_all(b"from the operator").await.unwrap();
    let mut got = [0u8; 17];
    tokio::time::timeout(LIMIT, near.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(&got, b"from the operator");
    near.write_all(b"from the service").await.unwrap();
    let mut got = [0u8; 16];
    tokio::time::timeout(LIMIT, far.read_exact(&mut got)).await.expect("in time").unwrap();
    assert_eq!(&got, b"from the service");
    // The same forward twice is refused; a cancel stops it once.
    assert!(handle.tcpip_forward("localhost", 2201).await.is_err(), "the same forward twice");
    handle.cancel_tcpip_forward("localhost", 2201).await.expect("cancelled");
    assert_eq!(*stand_in.stopped.lock().unwrap(), vec!["p-localhost-2201".to_string()]);
    // The connection's end stops the rest.
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "bye", "").await;
    drop(handle);
    tokio::time::timeout(LIMIT, server).await.expect("the server ends").unwrap();
    let stopped = stand_in.stopped.lock().unwrap().clone();
    assert_eq!(stopped, vec!["p-localhost-2201".to_string(), format!("p-127.0.0.1-{GIVEN}")]);
}

/// No publisher (serve's default), or `--no-forwarding`: refused, with no
/// publish asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_way_out_a_forward_is_refused() {
    let stand_in = StandIn::default();
    let off = Settings {
        no_forwarding: true,
        remote: Some(Publisher(Arc::new(stand_in.clone()))),
        ..Settings::default()
    };
    for settings in [Settings::default(), off] {
        let connected = tokio::time::timeout(LIMIT, logged_in(settings, Client::default())).await;
        let (handle, _server) = connected.expect("in time");
        let asked = tokio::time::timeout(LIMIT, handle.tcpip_forward("127.0.0.1", 0)).await.expect("in time");
        assert!(asked.is_err(), "refused: {asked:?}");
    }
    assert!(stand_in.asked.lock().unwrap().is_empty(), "nothing was published");
}
