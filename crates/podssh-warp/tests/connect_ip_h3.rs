//! connect-ip over HTTP/3 against a server that podssh did not write: the
//! integration proxy of connect-ip-go (Diniboy1123's fork, which usque
//! takes; MIT), built at a pinned commit by
//! `.github/workflows/masque-h3-interop.yml`. Through it: sshd's banner,
//! then 1 MiB each way through an echo service, both on a host behind the
//! proxy that only the tunnel reaches.
//!
//! The run needs the proxy: with no `PODSSH_MASQUE_H3_URL` the test says
//! "did not run" and passes, so that the native suite runs everywhere.
//!
//! - `PODSSH_MASQUE_H3_URL`: the proxy's template, `https://proxy:443/vpn`;
//! - `PODSSH_MASQUE_H3_AT`: the address to dial for it, `ADDRESS:PORT`;
//! - `PODSSH_MASQUE_H3_PIN`: the SHA-256 of the proxy's certificate;
//! - `PODSSH_MASQUE_H3_SSH`: sshd behind the proxy, `ADDRESS:PORT`;
//! - `PODSSH_MASQUE_H3_ECHO`: an echo service behind it, `ADDRESS:PORT`.
#![cfg(feature = "h3")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use podssh_warp::h3::server::Server;
use podssh_warp::Warp;
use podssh_ws::Trust;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The bound on each wait of the test.
const LIMIT: Duration = Duration::from_secs(20);
/// The bytes that go each way through the echo service.
const MIB: usize = 1 << 20;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn addr(name: &str) -> SocketAddr {
    let text = env(name).unwrap_or_else(|| panic!("{name} is needed with PODSSH_MASQUE_H3_URL"));
    text.trim().parse().unwrap_or_else(|_| panic!("{name}={text}: ADDRESS:PORT"))
}

/// The tunnel to the proxy of the environment, or `None` with no proxy.
async fn tunnel() -> Option<Warp> {
    let Some(url) = env("PODSSH_MASQUE_H3_URL") else {
        println!("connect_ip_h3: did not run: PODSSH_MASQUE_H3_URL is not set (masque-h3-interop.yml sets it)");
        return None;
    };
    let pin = env("PODSSH_MASQUE_H3_PIN");
    let mut server = Server::parse(&url, pin.as_deref()).expect("the proxy's URL");
    if env("PODSSH_MASQUE_H3_AT").is_some() {
        server = server.at(addr("PODSSH_MASQUE_H3_AT"));
    }
    let began = Instant::now();
    let warp = Warp::open_server(&server, &Trust::Default, None, LIMIT).await.expect("the tunnel over HTTP/3");
    println!("connect_ip_h3: the tunnel opened in {} ms, at {}", began.elapsed().as_millis(), warp.endpoint);
    Some(warp)
}

/// One tunnel for both checks: connect-ip-go's proxy assigns each client
/// the same address and hands each a copy of the packets to it, so two
/// tunnels at once would reset each other's connections.
#[tokio::test(flavor = "multi_thread")]
async fn sshd_s_banner_and_a_mebibyte_each_way_through_connect_ip_go() {
    let Some(warp) = tunnel().await else { return };
    banner(&warp).await;
    mebibyte(&warp).await;
}

/// sshd's banner, `SSH-2.0-`, comes back through the tunnel; the planted
/// defect of a datagram with no Context ID fails here, as the proxy then
/// reads the packet's first byte as a Context ID and drops it.
async fn banner(warp: &Warp) {
    let mut stream = warp.stack().connect(addr("PODSSH_MASQUE_H3_SSH"), LIMIT).await.expect("TCP to sshd inside");
    let mut banner = Vec::new();
    let read = tokio::time::timeout(LIMIT, async {
        let mut byte = [0u8; 1];
        while !banner.ends_with(b"\n") && banner.len() < 255 {
            if stream.read(&mut byte).await.expect("the banner") == 0 {
                break;
            }
            banner.push(byte[0]);
        }
    });
    read.await.expect("the banner within the limit");
    let line = String::from_utf8_lossy(&banner);
    assert!(line.starts_with("SSH-2.0-"), "{line:?}");
    println!("connect_ip_h3: {}", line.trim_end());
}

/// 1 MiB each way through the echo service, the bytes compared.
async fn mebibyte(warp: &Warp) {
    let stream = warp.stack().connect(addr("PODSSH_MASQUE_H3_ECHO"), LIMIT).await.expect("TCP to the echo inside");
    let (mut r, mut w) = tokio::io::split(stream);
    let sent: Vec<u8> = (0..MIB).map(|i| (i * 31 % 251) as u8).collect();
    let began = Instant::now();
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            w.write_all(&sent).await.expect("1 MiB out");
            w.flush().await.expect("the flush");
        })
    };
    let mut got = vec![0u8; MIB];
    tokio::time::timeout(Duration::from_secs(120), r.read_exact(&mut got))
        .await
        .expect("1 MiB back within 120 s")
        .expect("1 MiB back");
    writer.await.unwrap();
    assert!(got == sent, "the bytes that came back are not those sent");
    println!("connect_ip_h3: 1 MiB each way in {} ms", began.elapsed().as_millis());
}
