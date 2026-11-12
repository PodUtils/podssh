//! The key exchange's guess (T-752), against russh's own server in this
//! process, on a link whose server's bytes come late: the first login
//! records the host's first names, and the next sends its KEXINIT with its
//! identification and the guessed packet behind it, so the server answers a
//! wait sooner. A host whose names changed ignores the guess, and the login
//! goes on the usual way. Its own binary: the record is the process's, and
//! no other test's login meets it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::run::{connect_hops, disconnect_all};
use podssh_ssh::{accepted::KeptFile, kex_first};
use podssh_ssh::{Agent, Hop, Log, LogLevel, Options, StrictHostKeyChecking};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth};

/// The server's bytes come this late.
const FAR: Duration = Duration::from_millis(400);
const LIMIT: Duration = Duration::from_secs(20);

#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Option<String>>>);

impl KeptFile for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

#[derive(Clone)]
struct Open;

impl server::Handler for Open {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
}

/// The server's end of a link whose bytes to the client each come `late`
/// after the server wrote them.
fn link_late(late: Duration) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, near) = tokio::io::duplex(1 << 16);
    let (far, server_end) = tokio::io::duplex(1 << 16);
    let (mut near_read, mut near_write) = tokio::io::split(near);
    let (mut far_read, mut far_write) = tokio::io::split(far);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut near_read, &mut far_write).await;
    });
    let (due, mut queue) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(n) = far_read.read(&mut buf).await {
            if n == 0 || due.send((tokio::time::Instant::now() + late, buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, chunk)) = queue.recv().await {
            tokio::time::sleep_until(at).await;
            if near_write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = near_write.shutdown().await;
    });
    (client_end, server_end)
}

/// One login to a server of `config` over the late link: how long it took.
async fn login(config: Arc<server::Config>) -> Duration {
    let (client_end, server_end) = link_late(FAR);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Open).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "guess.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop, "podtest".into());
    opts.connect_timeout = LIMIT;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identities_only = true;
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.log_level = LogLevel::Quiet;
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let start = std::time::Instant::now();
    let handles =
        tokio::time::timeout(LIMIT, connect_hops(client_end, &opts, &log)).await.expect("in time").expect("logged in");
    let took = start.elapsed();
    disconnect_all(&handles).await;
    took
}

fn config(host: &PrivateKey, kex_first: Option<russh::kex::Name>) -> Arc<server::Config> {
    let mut config = server::Config::default();
    config.keys.push(host.clone());
    if let Some(first) = kex_first {
        let mut order = vec![first];
        order.extend(config.preferred.kex.iter().filter(|k| **k != first).cloned());
        config.preferred.kex = order.into();
    }
    Arc::new(config)
}

#[tokio::test]
async fn a_second_login_guesses_the_key_exchange_and_an_answer_comes_sooner_and_a_wrong_guess_costs_none() {
    let memory = Memory::default();
    assert!(kex_first::keep_in(Box::new(memory.clone())));
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let first = login(config(&host, None)).await;
    assert!(memory.load().is_some_and(|text| text.lines().count() == 2), "the host's names were kept");
    let guessed = login(config(&host, None)).await;
    // The banner and the key exchange's offer, then its reply, then the
    // auth: three waits; with the guess the reply comes with the offer.
    assert!(guessed + FAR / 2 < first, "first {first:?}, with the guess {guessed:?}");
    // The server's first key exchange changed: the guess is wrong, ignored,
    // and the login takes the usual waits, no more.
    let changed = login(config(&host, Some(russh::kex::CURVE25519))).await;
    assert!(changed < first + FAR / 2, "first {first:?}, after a wrong guess {changed:?}");
}
