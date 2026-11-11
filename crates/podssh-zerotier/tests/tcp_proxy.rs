//! The framing of `podssh_zerotier::relay` against ZeroTierOne's own
//! `tcp-proxy` (MPL-2.0, software that podssh did not write), which
//! `PODSSH_ZT_TCP_PROXY` names as `HOST:PORT`, already running, on a host
//! where it may send UDP to the loopback (`.github/workflows/zerotier-interop.yml`
//! builds it and runs it). A UDP echo of the test's own on the loopback:
//! the HELLO, then a datagram through the relay comes back from the echo's
//! address, whole. A datagram of 15 bytes, or one to a port of 1024 or less,
//! written as raw records past the encoder, the relay drops, as the
//! encoder's refusal says. Ignored unless the variable is set.

use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use podssh_zerotier::relay::{self, Records};

fn relay_at() -> Option<String> {
    std::env::var("PODSSH_ZT_TCP_PROXY").ok().filter(|v| !v.is_empty())
}

/// A UDP echo on the loopback, in a thread: its address.
fn echo() -> SocketAddrV4 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let at = match socket.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], from);
        }
    });
    at
}

/// What comes back on `tcp` within `wait`.
fn back(tcp: &mut TcpStream, records: &mut Records, wait: Duration) -> Vec<(SocketAddrV4, Vec<u8>)> {
    let deadline = Instant::now() + wait;
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    while Instant::now() < deadline && got.is_empty() {
        tcp.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        match tcp.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend(records.push(&buf[..n])),
            Err(_) => {}
        }
    }
    got
}

#[test]
#[ignore = "needs ZeroTierOne's tcp-proxy running: PODSSH_ZT_TCP_PROXY, zerotier-interop.yml"]
fn a_datagram_goes_through_zerotier_s_own_relay_and_one_that_it_drops_does_not() {
    let Some(at) = relay_at() else { return };
    let echo = echo();
    let mut tcp = TcpStream::connect(&at).expect("the relay takes a TCP connection");
    tcp.write_all(&relay::hello(podssh_zerotier::version())).unwrap();
    let mut records = Records::default();
    let datagram: Vec<u8> = (0..200u8).collect();
    tcp.write_all(&relay::encode(echo, &datagram).unwrap()).unwrap();
    assert_eq!(back(&mut tcp, &mut records, Duration::from_secs(5)), [(echo, datagram)], "the echo through the relay");
    // 15 bytes, as raw records past the encoder's refusal: nothing comes back.
    let short = [0x17, 3, 3, 0, 22, 4, 127, 0, 0, 1];
    let mut raw = short.to_vec();
    raw.extend_from_slice(&echo.port().to_be_bytes());
    raw.extend_from_slice(&[9u8; 15]);
    tcp.write_all(&raw).unwrap();
    assert!(back(&mut tcp, &mut records, Duration::from_secs(2)).is_empty(), "the relay dropped 15 bytes");
    assert!(relay::encode(echo, &[9u8; 15]).is_err(), "and the encoder refuses them");
}
