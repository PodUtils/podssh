//! The one-POST form of the HTTP road over HTTP/2 (T-622): one stream, a
//! POST to `/v1/http/one/HOST/PORT` whose DATA is the way up and whose
//! answer's DATA is the way down. The stream goes to the role's routes as
//! the same request of HTTP/1.1 on a pipe in memory, its body in chunks;
//! once the role's `200` came, with its mark, the stream's DATA goes up as
//! chunks and the answer's chunks come down as DATA, each as it comes. A
//! refusal of the role goes back whole, with its status and fields.

use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::stream::{answer, fields, read_head, refuse, route};
use crate::serve::Config;

/// The largest chunk of the answer passed down in one DATA frame.
const DOWN: usize = 64 * 1024;
/// The longest line of a chunk's size, with its extensions.
const LINE_MAX: u64 = 1024;

/// The one-POST form on the stream of `request`.
pub(super) async fn serve(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
) {
    let (parts, mut body) = request.into_parts();
    let Some(authority) = parts.uri.authority().map(|a| a.to_string()) else {
        return refuse(&mut respond, 400, "a request names its :authority");
    };
    let target = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let mut head = format!("POST {target} HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\n");
    fields(&mut head, &parts.headers, &["host", "content-length"]);
    head.push_str("\r\n");
    let Some(mut pipe) = route(head.into_bytes(), cfg, sni, from).await else {
        return refuse(&mut respond, 502, "relay: the request reached no route");
    };
    let Some((status, buf, end)) = read_head(&mut pipe).await else {
        return refuse(&mut respond, 502, "relay: no answer to the request");
    };
    if status != 200 {
        return answer(&mut pipe, buf, respond).await;
    }
    let Ok(opened) = http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(opened, false) else { return };
    let (from_role, mut to_role) = tokio::io::split(pipe);
    // The bytes up: each DATA frame as one chunk, and the stream's end as
    // the body's last chunk.
    let up = tokio::spawn(async move {
        while let Some(data) = body.data().await {
            let Ok(data) = data else { return };
            let _ = body.flow_control().release_capacity(data.len());
            if data.is_empty() {
                continue;
            }
            let mut chunk = format!("{:x}\r\n", data.len()).into_bytes();
            chunk.extend_from_slice(&data);
            chunk.extend_from_slice(b"\r\n");
            if to_role.write_all(&chunk).await.is_err() || to_role.flush().await.is_err() {
                return;
            }
        }
        let _ = to_role.write_all(b"0\r\n\r\n").await;
        let _ = to_role.flush().await;
    });
    // The bytes down: the answer's chunks, after its head, as DATA.
    let rest = std::io::Cursor::new(buf[end..].to_vec());
    let mut reader = BufReader::new(rest.chain(from_role));
    let ended = down(&mut reader, &mut send).await;
    up.abort();
    match ended {
        // The target's end: the stream's END_STREAM.
        Ok(()) => {
            let _ = send.send_data(Bytes::new(), true);
        }
        // A cut of the role (a limit met): a reset, as HTTP/1.1 ends with
        // no last chunk.
        Err(()) => send.send_reset(h2::Reason::CANCEL),
    }
}

/// The answer's chunks to `send` as DATA, waiting for the client's window;
/// `Ok` at the last chunk, `Err` at a cut or a framing that breaks.
async fn down<R>(reader: &mut BufReader<R>, send: &mut h2::SendStream<Bytes>) -> Result<(), ()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let mut line = Vec::new();
        let n = (&mut *reader).take(LINE_MAX).read_until(b'\n', &mut line).await.map_err(|_| ())?;
        if n == 0 || !line.ends_with(b"\n") {
            return Err(());
        }
        let text = String::from_utf8_lossy(&line);
        let hex = text.trim().split(';').next().unwrap_or_default();
        let mut left = usize::from_str_radix(hex, 16).map_err(|_| ())?;
        if left == 0 {
            return Ok(());
        }
        while left > 0 {
            let mut data = vec![0u8; left.min(DOWN)];
            reader.read_exact(&mut data).await.map_err(|_| ())?;
            left -= data.len();
            give(send, Bytes::from(data)).await?;
        }
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.map_err(|_| ())?;
        if &crlf != b"\r\n" {
            return Err(());
        }
    }
}

/// `data` as DATA, once the client's window has room for each part of it.
async fn give(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<(), ()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let room = std::future::poll_fn(|cx| send.poll_capacity(cx)).await.ok_or(())?.map_err(|_| ())?;
        let part = data.split_to(room.min(data.len()));
        send.send_data(part, false).map_err(|_| ())?;
    }
    Ok(())
}
