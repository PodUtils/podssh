//! A target for the tests of each road's end of input (T-699). It sends a
//! first piece at once, so that the road is ready and this side ends its
//! input, then waits, then sends the rest of 1 MiB and closes: the rest is
//! in flight while this side's input has ended. A road that ends the
//! session at that end loses the rest; one that waits for the peer's end,
//! or half-closes, carries it whole.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const MIB: usize = 1 << 20;
/// The first piece: the road's first word, which Trojan's reader of the
/// first bytes does not take for a fallback's `HTTP/`: it starts with 0.
pub const FIRST: usize = 16 * 1024;
/// Long enough for this side's end, and a Close that a planted road sends at
/// it, to reach the far end before the rest goes.
pub const PAUSE: Duration = Duration::from_millis(300);
/// The bound on the whole transfer.
pub const LIMIT: Duration = Duration::from_secs(30);

/// The bytes that the talker sends.
pub fn bytes() -> Vec<u8> {
    (0..MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8).collect()
}

/// A talker on the loopback: its port. What a client sends it is read and
/// dropped, so that no write of the client's waits.
pub async fn talker() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = tcp.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut rd, &mut tokio::io::sink()).await;
                });
                let all = bytes();
                if wr.write_all(&all[..FIRST]).await.is_err() {
                    return;
                }
                tokio::time::sleep(PAUSE).await;
                let _ = wr.write_all(&all[FIRST..]).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    port
}

/// `stream` read to its end, within [`LIMIT`].
pub async fn to_end(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut got = Vec::new();
    let read = tokio::time::timeout(LIMIT, stream.read_to_end(&mut got)).await;
    read.expect("the end of the stream within the limit").expect("a clean end");
    got
}

/// Each byte that the talker sent, in order; a short copy says how short.
pub fn assert_whole(got: &[u8], road: &str) {
    assert_eq!(got.len(), MIB, "{road}: {} of {MIB} bytes came after the end of this side's input", got.len());
    assert!(got == bytes().as_slice(), "{road}: the bytes came changed");
}
