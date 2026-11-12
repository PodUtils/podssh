//! A session through a Hysteria 2 server: the bidirectional QUIC stream of
//! its TCP request, which holds the connection, its endpoint and HTTP/3's
//! control stream while it lives. The end of the writes finishes the
//! stream's way up, which the server passes on as TCP's half-close; when
//! the session goes, the connection closes with HTTP/3's code of no error,
//! as Hysteria's client closes it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pod_quic::noq::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// HTTP/3's `H3_NO_ERROR` (RFC 9114, section 8.1).
pub const H3_NO_ERROR: u32 = 0x100;

/// The session's stream.
pub struct Stream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    endpoint: Endpoint,
    /// HTTP/3's control stream, open for the connection's life: a peer
    /// takes its end as an error of the connection (RFC 9114, 6.2.1).
    _control: SendStream,
}

impl Stream {
    pub fn new(
        (send, recv): (SendStream, RecvStream),
        connection: Connection,
        endpoint: Endpoint,
        control: SendStream,
    ) -> Stream {
        Stream { send, recv, connection, endpoint, _control: control }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(H3_NO_ERROR), b"");
        self.endpoint.close(VarInt::from_u32(H3_NO_ERROR), b"");
    }
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
