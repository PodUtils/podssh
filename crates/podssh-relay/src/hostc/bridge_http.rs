//! A stream of an HTTP request (`HttpStream` of hostc's client, `streams.ts`
//! at `c19ff67`), bridged to the pipe: the head of the request, then its
//! body in chunks as `DATA` comes, each granted back with `WINDOW` once the
//! pipe took it; the pipe's answer as `HEAD`, then its body in `DATA` of
//! 64 KiB at most, each sent only within the server's grants, then `END`.
//! The grants back are of the bytes taken, never more: the window stays
//! 256 KiB, so the node holds at most that of a request that its side does
//! not read (T-742's Decision).

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use super::bridge::{In, Parts};
use super::wire::{self, Head, Kind};
use super::{MAX_CHUNK, STREAM_WINDOW};
use crate::quick::origin::{self, Asked, BodyHead};

/// The headers of one hop in an answer, which the server does not take.
const HOP: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade"];
/// The longest line of a chunk's size, or of a trailer.
const MAX_LINE: usize = 4096;

/// The request of `parts`, bridged until it ends.
pub(super) async fn run(mut parts: Parts) {
    let host = parts.open.header("host").unwrap_or(&parts.name).to_string();
    let open = &parts.open;
    let asked = Asked {
        method: open.method.clone(),
        target: open.path.clone(),
        host,
        headers: open.headers.clone(),
        websocket: false,
    };
    let body = if open.body { BodyHead::Chunked } else { BodyHead::Length(0) };
    let head = match asked.head_with(body) {
        Ok(head) => head,
        Err(why) => return parts.reset(&format!("the request: {why}")).await,
    };
    let method = open.method.clone();
    let pipe = std::mem::replace(&mut parts.pipe, tokio::io::duplex(1).0);
    let (mut from_pipe, mut to_pipe) = tokio::io::split(pipe);
    if to_pipe.write_all(&head).await.is_err() {
        return parts.reset("the node took no request").await;
    }
    let credit = Arc::new(Semaphore::new(STREAM_WINDOW));
    let mut from = std::mem::replace(&mut parts.from, tokio::sync::mpsc::unbounded_channel().1);
    // The server's frames: the request's body, its end, and the grants of
    // the answer's body, until the answer has gone or the stream is reset.
    let inbound = async {
        while let Some(given) = from.recv().await {
            match given {
                In::Data(bytes) => {
                    let mut chunk = format!("{:x}\r\n", bytes.len()).into_bytes();
                    chunk.extend_from_slice(&bytes);
                    chunk.extend_from_slice(b"\r\n");
                    // Granted back only once the pipe took the bytes.
                    if to_pipe.write_all(&chunk).await.is_err() {
                        return;
                    }
                    parts.taken(bytes.len());
                    if !parts.send(Kind::Window, &wire::window(bytes.len() as u32)).await {
                        return;
                    }
                }
                In::End(_) => {
                    if to_pipe.write_all(b"0\r\n\r\n").await.is_err() {
                        return;
                    }
                }
                In::Window(granted) => credit.add_permits(granted as usize),
                In::Text(_) => {}
                In::Reset => return,
            }
        }
    };
    let outbound = answer(&parts, &method, &mut from_pipe, &credit);
    tokio::select! {
        // A reset, or the socket's end: the pipe closes, and the node's side ends.
        () = inbound => {}
        result = outbound => {
            if let Err(why) = result {
                parts.reset(&why).await;
            }
        }
    }
}

/// The pipe's answer as `HEAD`, `DATA` within the server's grants, and `END`.
async fn answer<R: AsyncRead + Unpin>(
    parts: &Parts,
    method: &str,
    from: &mut R,
    credit: &Semaphore,
) -> Result<(), String> {
    let read = tokio::time::timeout(origin::ANSWER_WAIT, origin::read_answer(from)).await;
    let (head, rest) = read.map_err(|_| "no answer of the node within its time".to_string())??;
    if head.status < 100 || head.status > 599 || head.status == 101 {
        return Err(format!("the node answered {}, which a request takes no", head.status));
    }
    let body = wire::has_body(method, head.status);
    let headers = head.headers.iter().filter(|(name, _)| !HOP.contains(&name.as_str())).cloned().collect();
    let sent = Head { status: head.status, headers, body, protocol: None };
    if !parts.send(Kind::Head, &sent.bytes()).await || !body {
        return Ok(());
    }
    let chunked =
        head.headers.iter().any(|(n, v)| n == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let length = match chunked {
        true => None,
        false => head
            .length()
            .map(|l| l.trim().parse::<u64>().map_err(|_| "a bad Content-Length".to_string()))
            .transpose()?,
    };
    let mut reader = Body { buf: rest, chunked, left: length, ended: false, in_chunk: 0 };
    while let Some(bytes) = reader.next(from, MAX_CHUNK).await? {
        // Within the server's window alone: past it, the pipe waits, and
        // the node's side with it.
        let permit = credit.acquire_many(bytes.len() as u32).await.map_err(|_| "the stream ended".to_string())?;
        permit.forget();
        if !parts.send(Kind::Data, &bytes).await {
            return Ok(());
        }
    }
    parts.send(Kind::End, &[]).await;
    Ok(())
}

/// An answer's body: of a length, in chunks, or until the pipe ends.
pub(super) struct Body {
    pub buf: Vec<u8>,
    pub chunked: bool,
    /// The bytes left of a length; none for chunks or the pipe's end.
    pub left: Option<u64>,
    pub ended: bool,
    /// The bytes left of the chunk now.
    pub in_chunk: usize,
}

impl Body {
    /// The next piece of the body, `max` bytes at most; none at its end.
    pub async fn next<R: AsyncRead + Unpin>(&mut self, from: &mut R, max: usize) -> Result<Option<Vec<u8>>, String> {
        if self.ended {
            return Ok(None);
        }
        if self.chunked {
            return self.next_chunk(from, max).await;
        }
        let want = match self.left {
            Some(0) => {
                self.ended = true;
                return Ok(None);
            }
            Some(left) => max.min(left as usize),
            None => max,
        };
        if self.buf.is_empty() && !self.fill(from).await? {
            self.ended = true;
            return match self.left {
                None => Ok(None),
                Some(left) => Err(format!("the node's answer ended {left} bytes short")),
            };
        }
        let piece: Vec<u8> = self.buf.drain(..want.min(self.buf.len())).collect();
        if let Some(left) = &mut self.left {
            *left -= piece.len() as u64;
        }
        Ok(Some(piece))
    }

    async fn next_chunk<R: AsyncRead + Unpin>(&mut self, from: &mut R, max: usize) -> Result<Option<Vec<u8>>, String> {
        if self.in_chunk == 0 {
            let line = self.line(from).await?;
            let size = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size, 16).map_err(|_| "a bad size of a chunk".to_string())?;
            if size == 0 {
                // The trailers, which go nowhere, up to the empty line.
                while !self.line(from).await?.is_empty() {}
                self.ended = true;
                return Ok(None);
            }
            self.in_chunk = size;
        }
        if self.buf.is_empty() && !self.fill(from).await? {
            return Err("the node's answer ended inside a chunk".into());
        }
        let piece: Vec<u8> = self.buf.drain(..max.min(self.in_chunk).min(self.buf.len())).collect();
        self.in_chunk -= piece.len();
        if self.in_chunk == 0 && !self.line(from).await?.is_empty() {
            return Err("a chunk with no CRLF after it".into());
        }
        Ok(Some(piece))
    }

    /// One line, with no CRLF.
    async fn line<R: AsyncRead + Unpin>(&mut self, from: &mut R) -> Result<String, String> {
        loop {
            if let Some(at) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..at + 2).collect();
                return Ok(String::from_utf8_lossy(&line[..at]).into_owned());
            }
            if self.buf.len() > MAX_LINE {
                return Err("a line of the node's answer is too long".into());
            }
            if !self.fill(from).await? {
                return Err("the node's answer ended inside a line".into());
            }
        }
    }

    /// More bytes from the pipe; false at its end.
    async fn fill<R: AsyncRead + Unpin>(&mut self, from: &mut R) -> Result<bool, String> {
        let mut chunk = vec![0u8; 16 * 1024];
        let n = from.read(&mut chunk).await.map_err(|e| format!("the node's answer: {e}"))?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }
}

#[cfg(test)]
#[path = "bridge_http_tests.rs"]
mod tests;
