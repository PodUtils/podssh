//! The Dev Tunnels forward road (T-755) against pod-devtunnel's stand-in on
//! the loopback (the management API, the relay WebSocket with its
//! subprotocol, the host's SSH with no user authentication, `direct-tcpip`):
//! a session of SSH to a server of the test behind the tunnel completes its
//! handshake and runs a command; a relay that goes away ends a stream with
//! a named error, and a new stream after it works; no token reaches a line,
//! a `Debug` or the words of a failure.
#![cfg(feature = "devtunnel-standin")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_core::Class;
use pod_devtunnel::standin::{Plan, Port, Standin, TOKEN_PREFIX};
use podssh_relay::devtunnel::{self, lines, parse_token, Road, Step};
use podssh_ws::{ProxyChoice, Trust};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The user's token of the tests: a made-up value.
const USER_TOKEN: &str = "made-up-user-token-of-podssh-devtunnel";
/// Each wait of the test.
const LIMIT: Duration = Duration::from_secs(20);
/// The port of the SSH server behind the tunnel, and of the echo.
const SSH_PORT: u16 = 2222;
const ECHO_PORT: u16 = 22;

/// The SSH server of the test: any user with no authentication, and an
/// `exec` that answers its command and exits 0.
#[derive(Clone)]
struct Server;

impl russh::server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let answer = format!("ran: {}\n", String::from_utf8_lossy(data));
        session.data(channel, answer.into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

/// The SSH server on a port of the loopback.
async fn ssh_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
    let at = listener.local_addr().unwrap();
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        methods: MethodSet::from(&[MethodKind::None][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..russh::server::Config::default()
    });
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(running) = russh::server::run_stream(config, tcp, Server).await {
                    let _ = running.await;
                }
            });
        }
    });
    at
}

/// The client of the test's session: the server is its own.
struct Client;

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// The stand-in with the SSH server at `ssh` and an echo.
async fn standin(ssh: SocketAddr) -> Standin {
    let mut plan = Plan::echo("github", USER_TOKEN);
    plan.ports = vec![(ECHO_PORT, Port::Echo), (SSH_PORT, Port::Forward(ssh))];
    Standin::start(plan).await.expect("the stand-in")
}

/// The road to the stand-in's tunnel, as podssh makes it, with no wait
/// between the tries of a reconnect. Direct: a proxy of the host must not
/// carry a dial to the loopback.
fn road(standin: &Standin, token: &str) -> Road {
    let mut settings = devtunnel::settings(Some(&standin.base())).expect("the stand-in's base");
    settings.timeout = LIMIT;
    settings.backoff = |_| Duration::ZERO;
    settings.reconnect_tries = 3;
    let user = parse_token(&format!("github {token}")).expect("a token line");
    Road::new("standin-box", user, settings, Trust::Default, ProxyChoice::Direct).expect("a tunnel name")
}

/// Each line that the road said, kept.
fn kept_report() -> (pod_core::Report, Arc<Mutex<Vec<String>>>) {
    let kept: Arc<Mutex<Vec<String>>> = Arc::default();
    let (a, b) = (kept.clone(), kept.clone());
    let info: lines::Say = Arc::new(move |l| a.lock().unwrap().push(l.to_string()));
    let verbose: lines::Say = Arc::new(move |l| b.lock().unwrap().push(l.to_string()));
    (lines::report(info, verbose), kept)
}

#[tokio::test]
async fn devtunnel_a_session_to_an_ssh_server_behind_the_tunnel_runs_a_command() {
    let standin = standin(ssh_server().await).await;
    let (report, kept) = kept_report();
    let stream = tokio::time::timeout(LIMIT, road(&standin, USER_TOKEN).open(SSH_PORT, report))
        .await
        .expect("the open within its limit")
        .unwrap_or_else(|e| panic!("open: {}", e.chain()));
    let config = Arc::new(russh::client::Config::default());
    let mut ssh = russh::client::connect_stream(config, stream, Client).await.expect("the SSH handshake");
    assert!(ssh.authenticate_none("tester").await.unwrap().success(), "no authentication asked");
    let mut channel = ssh.channel_open_session().await.unwrap();
    channel.exec(true, "uname").await.unwrap();
    let (mut out, mut status) = (Vec::new(), None);
    while let Some(msg) = tokio::time::timeout(LIMIT, channel.wait()).await.expect("the command's answer") {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    assert_eq!((String::from_utf8_lossy(&out).as_ref(), status), ("ran: uname\n", Some(0)));
    let seen = standin.seen();
    assert_eq!(seen.channels, [("127.0.0.1".to_string(), u32::from(SSH_PORT), "127.0.0.1".to_string(), 0)]);
    assert_eq!(seen.users, ["tunnel"]);
    assert!(kept.lock().unwrap().iter().any(|l| l.contains("standin-box")), "{:?}", kept.lock().unwrap());
}

/// A read within the test's limit.
async fn read_some(stream: &mut devtunnel::Tunneled) -> std::io::Result<usize> {
    tokio::time::timeout(LIMIT, stream.read(&mut [0u8; 64])).await.expect("an end of the read")
}

#[tokio::test]
async fn devtunnel_a_relay_that_goes_away_ends_a_stream_by_name_and_a_new_stream_works() {
    let standin = standin(ssh_server().await).await;
    let (report, kept) = kept_report();
    let mut first = road(&standin, USER_TOKEN).open(ECHO_PORT, report).await.unwrap();
    first.write_all(b"a").await.unwrap();
    assert_eq!(read_some(&mut first).await.unwrap(), 1);

    standin.drop_relays();
    let e = read_some(&mut first).await.unwrap_err();
    assert!(devtunnel::session_ended(&e), "not the named end of the session: {e:?}");
    assert_eq!(e.to_string(), devtunnel::SESSION_ENDED);

    let mut second = devtunnel::open(first.relay(), ECHO_PORT).await.unwrap_or_else(|e| panic!("{}", e.chain()));
    second.write_all(b"again").await.unwrap();
    let mut back = [0u8; 5];
    second.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"again");
    assert_eq!((second.relay().sessions(), second.stream().session(), standin.minted()), (2, 2, 2));
    // The user's line names the reconnect.
    assert!(kept.lock().unwrap().iter().any(|l| l.contains("reconnect")), "{:?}", kept.lock().unwrap());
}

#[tokio::test]
async fn devtunnel_a_refusal_names_its_stage_and_class() {
    let standin = standin(ssh_server().await).await;
    let refused = road(&standin, "made-up-other-token").open(ECHO_PORT, lines::quiet()).await.unwrap_err();
    assert_eq!((devtunnel::step_of(&refused), refused.class), (Some(Step::Management), Class::Refused));
    assert_eq!(devtunnel::stage_of(&refused), "management");
    let port = road(&standin, USER_TOKEN).open(9, lines::quiet()).await.unwrap_err();
    assert_eq!((devtunnel::stage_of(&port), port.class), ("channel", Class::Unavailable));
}

#[tokio::test]
async fn devtunnel_no_token_reaches_a_line_a_debug_or_a_failure() {
    let standin = standin(ssh_server().await).await;
    let (report, kept) = kept_report();
    let road = road(&standin, USER_TOKEN);
    let mut stream = road.open(ECHO_PORT, report).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    let _ = read_some(&mut stream).await;
    standin.drop_relays();
    let _ = read_some(&mut stream).await;
    let again = devtunnel::open(stream.relay(), ECHO_PORT).await.unwrap();
    let mut texts = vec![format!("{road:?} {stream:?} {again:?} {}", road.shown())];
    standin.refuse_upgrades(100);
    standin.drop_relays();
    let reconnect = devtunnel::open(stream.relay(), ECHO_PORT).await.unwrap_err();
    assert_eq!(devtunnel::stage_of(&reconnect), "reconnect");
    texts.push(format!("{} {reconnect:?}", reconnect.chain()));
    standin.refuse_user();
    let refused = road.open(ECHO_PORT, lines::quiet()).await.unwrap_err();
    texts.push(format!("{} {refused:?}", refused.chain()));
    texts.extend(kept.lock().unwrap().iter().cloned());
    assert!(texts.len() > 4, "{texts:?}");
    for text in &texts {
        assert!(!text.contains(USER_TOKEN) && !text.contains(TOKEN_PREFIX), "a token in: {text}");
    }
}
