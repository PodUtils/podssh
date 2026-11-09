//! The check of a roost's TARGET (feature `pair`, T-166) against servers on
//! the loopback: SSH's version line passes and stays in the stream for the
//! session, whole, in two pieces, or after a greeting (T-702); another
//! service, a silence and a close are refused, each with what came back.
//! Each session's dial of a roost runs the same check.
#![cfg(feature = "pair")]

use std::time::Duration;

use podssh_relay::reverse::sshd::{check, NotSshd};
use podssh_relay::reverse::tcp::dial_target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HTTP: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";

/// A TARGET on the loopback that writes `bytes` to each connection, then
/// keeps it for `keep`: its port.
async fn target(bytes: &'static [u8], keep: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(bytes).await;
                tokio::time::sleep(keep).await;
            });
        }
    });
    port
}

/// A TARGET that writes `first`, waits `pause`, writes `then`, and keeps
/// each connection for 5 s: its port.
async fn target_in_parts(first: &'static [u8], pause: Duration, then: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(first).await;
                tokio::time::sleep(pause).await;
                let _ = stream.write_all(then).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    port
}

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

#[tokio::test]
async fn the_check_takes_no_byte_of_the_stream() {
    let port = target(b"SSH-2.0-roost-test\r\nafter", Duration::from_secs(5)).await;
    let mut stream = connect(port).await;
    assert_eq!(check(&stream, Duration::from_secs(5)).await, Ok("SSH-2.0-roost-test".into()));
    let mut got = vec![0u8; 25];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, b"SSH-2.0-roost-test\r\nafter");
}

#[tokio::test]
async fn a_service_that_is_not_sshd_is_refused_with_its_line() {
    let port = target(HTTP, Duration::from_secs(5)).await;
    let refused = check(&connect(port).await, Duration::from_secs(5)).await.unwrap_err();
    assert!(refused.is_other(), "{refused:?}");
    assert!(refused.to_string().contains("\"HTTP/1.1 400 Bad Request\" first"), "{refused}");
}

#[tokio::test]
async fn a_silent_target_is_refused_after_the_limit_with_what_came() {
    let limit = Duration::from_millis(300);
    let port = target(b"", Duration::from_secs(5)).await;
    let refused = check(&connect(port).await, limit).await.unwrap_err();
    assert_eq!(refused, NotSshd::Silent { after: limit, seen: String::new() });
    let port = target(b"SSH-2.", Duration::from_secs(5)).await;
    let refused = check(&connect(port).await, limit).await.unwrap_err();
    assert_eq!(refused, NotSshd::Silent { after: limit, seen: "SSH-2.".into() });
    assert!(!refused.is_other());
}

/// The first piece is shorter than `SSH-`; the check waits for the rest,
/// and leaves both pieces in the stream (T-702).
#[tokio::test]
async fn a_version_line_in_two_pieces_passes() {
    let port = target_in_parts(b"SS", Duration::from_millis(200), b"H-2.0-roost-test\r\n").await;
    let mut stream = connect(port).await;
    assert_eq!(check(&stream, Duration::from_secs(5)).await, Ok("SSH-2.0-roost-test".into()));
    let mut got = vec![0u8; 20];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, b"SSH-2.0-roost-test\r\n");
}

/// RFC 4253, section 4.2: a server may greet before its version line, in
/// one write or a moment before it, and the direct road reaches it; the
/// roost serves it too, with each byte left for the session (T-702).
#[tokio::test]
async fn a_greeting_before_the_version_line_passes() {
    let port = target(b"Welcome to the lab\r\nSSH-2.0-roost-test\r\n", Duration::from_secs(5)).await;
    let mut stream = connect(port).await;
    assert_eq!(check(&stream, Duration::from_secs(5)).await, Ok("SSH-2.0-roost-test".into()));
    let mut got = vec![0u8; 20];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, b"Welcome to the lab\r\n", "the greeting stays in the stream");
    let port = target_in_parts(b"Welcome to the lab\r\n", Duration::from_millis(200), b"SSH-2.0-roost-test\r\n").await;
    assert_eq!(check(&connect(port).await, Duration::from_secs(5)).await, Ok("SSH-2.0-roost-test".into()));
}

/// An HTTP answer alone, from a server that closes after it: another
/// service, named by its first line at once, not at the limit, though a
/// peek never sees the close.
#[tokio::test]
async fn a_service_that_closes_after_its_answer_is_refused_at_once() {
    let port = target(HTTP, Duration::ZERO).await;
    let started = std::time::Instant::now();
    let refused = check(&connect(port).await, Duration::from_secs(5)).await.unwrap_err();
    assert_eq!(refused, NotSshd::Other("HTTP/1.1 400 Bad Request".into()));
    assert!(started.elapsed() < Duration::from_secs(3), "refused after {:?}", started.elapsed());
}

#[tokio::test]
async fn a_target_that_closes_at_once_is_refused() {
    let port = target(b"", Duration::ZERO).await;
    let refused = check(&connect(port).await, Duration::from_secs(5)).await.unwrap_err();
    // A close is a FIN; a host that answers it with a reset fails the peek
    // instead.
    assert!(matches!(refused, NotSshd::Closed | NotSshd::Failed(_)), "{refused:?}");
}

/// Each session of a roost dials with the check, and a node that is no
/// roost dials as before: the same service passes one and not the other.
#[tokio::test]
async fn a_roost_s_dial_refuses_what_a_node_s_dial_takes() {
    let port = target(HTTP, Duration::from_secs(5)).await;
    let limit = Duration::from_secs(5);
    assert!(dial_target("127.0.0.1", port, limit, false).await.is_ok());
    let why = dial_target("127.0.0.1", port, limit, true).await.unwrap_err();
    let said = format!("127.0.0.1:{port} is not an SSH server: it sent \"HTTP/1.1 400 Bad Request\" first");
    assert!(why.starts_with(&said), "{why}");
    let ssh = target(b"SSH-2.0-roost-test\r\n", Duration::from_secs(5)).await;
    let mut stream = dial_target("127.0.0.1", ssh, limit, true).await.unwrap();
    let mut line = vec![0u8; 20];
    stream.read_exact(&mut line).await.unwrap();
    assert_eq!(line, b"SSH-2.0-roost-test\r\n", "the session's client reads sshd's line itself");
}
