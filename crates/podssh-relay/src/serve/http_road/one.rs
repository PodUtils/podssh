//! The one-POST form of the HTTP road (T-622): `POST
//! /v1/http/one/HOST/PORT[?family=4|6]` with the forward token and a body
//! in chunks, the client's bytes up as they come; answered at once with its
//! head and [`MARK`], then the target's bytes down in chunks as they come.
//! One request carries the session both ways, on one connection, with no
//! session id: where a hop passes a body as it comes, no request for each
//! batch. A hop that holds a request's body, or an answer's, to its end
//! holds the mark too, and the client's bound on the mark takes the split
//! form. The checks and the dial are the open's ([`super::dial`]); the
//! limits are a session's of the road: idle, time and bytes, each of which
//! ends the answer with no last chunk, so that the client reads a cut, not
//! an end. The target's end is the answer's last chunk; the body's last
//! chunk is TCP's half-close to the target.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::http::request::Request;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::Instant;

use super::answers::{refuse, write};
use crate::serve::Config;

/// The form's path, before `HOST/PORT`.
pub const ONE: &str = "/v1/http/one/";
/// The answer's first bytes, at once: what tells the client that no hop
/// holds the answer, nor the request's body.
pub const MARK: &[u8] = b"podssh-http-one 1\n";
/// The bytes asked of the target in each read.
const READ: usize = 64 * 1024;
/// The longest line of a chunk's size, with its extensions.
const LINE_MAX: usize = 1024;
/// How often the limits are looked at.
const TICK: Duration = Duration::from_millis(500);

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The sessions of this form that run now, which the bound on the road's
/// sessions at once counts with the split form's.
pub fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

/// Whether `path`, with no query, is the form's.
pub fn serves(path: &str) -> bool {
    path.starts_with(ONE)
}

/// One count in [`LIVE`], given back when the session ends however it ends.
struct Counted;

impl Counted {
    fn take() -> Counted {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Counted
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What the session moved, and when it last moved any, for its limits.
struct Moved {
    bytes: AtomicU64,
    heard: Mutex<Instant>,
}

impl Moved {
    /// Of `n` bytes, the ones that the cap `cap` still lets through.
    fn take(&self, n: usize, cap: u64) -> usize {
        let before = self.bytes.fetch_add(n as u64, Ordering::SeqCst);
        if let Ok(mut heard) = self.heard.lock() {
            *heard = Instant::now();
        }
        (n as u64).min(cap.saturating_sub(before)) as usize
    }
}

/// Serve the form's request `head` on `stream`, `pending` the bytes after
/// its head. The connection ends with the session.
pub async fn serve<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let chunked = head.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    if head.method != "POST" || head.minor != 1 || !chunked || head.has("content-length") {
        let why = "http: the one-POST form is a POST of HTTP/1.1 whose body goes in chunks";
        let _ = write(&mut stream, refuse(411, why, &[], false), false).await;
        let _ = stream.shutdown().await;
        return;
    }
    let Ok((tcp, meter)) = super::dial(&mut stream, &head, &cfg, ONE, false).await else {
        let _ = stream.shutdown().await;
        return;
    };
    let _counted = Counted::take();
    meter.start();
    let answer = "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Type: application/octet-stream\r\n\
                  Transfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n";
    let mut first = answer.as_bytes().to_vec();
    first.extend_from_slice(&chunk(MARK));
    if stream.write_all(&first).await.is_err() || stream.flush().await.is_err() {
        meter.settle();
        return;
    }
    cfg.event("http one open");
    let meter = Arc::new(meter);
    let moved = Arc::new(Moved { bytes: AtomicU64::new(0), heard: Mutex::new(Instant::now()) });
    let (from_client, to_client) = tokio::io::split(stream);
    let (from_target, to_target) = tcp.into_split();
    let reader = BufReader::new(std::io::Cursor::new(pending).chain(from_client));
    let mut up = tokio::spawn(up(reader, to_target, meter.clone(), moved.clone(), cfg.limits.bytes));
    let down = down(from_target, to_client, meter.clone(), moved.clone(), cfg.limits.bytes);
    let ended = tokio::select! {
        why = down => why,
        why = limits(&moved, &cfg) => why,
        // The client's body cut, not ended: the session is over.
        Ok(Err(why)) = &mut up => why,
    };
    up.abort();
    cfg.event(&format!("http one close: {ended}"));
    meter.settle();
}

/// The body's chunks to the target as they come; its last chunk is the
/// target's half-close, after which the target's bytes go on down. `Err`
/// is a body that was cut or broke its framing, or a target that failed.
async fn up<R, W>(
    mut body: BufReader<R>,
    mut to: W,
    meter: Arc<crate::serve::usage::Meter>,
    moved: Arc<Moved>,
    cap: u64,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ];
    loop {
        let size = line(&mut body).await?;
        let hex = size.split(';').next().unwrap_or_default().trim();
        let mut left = u64::from_str_radix(hex, 16).map_err(|_| format!("a chunk's size {hex:?}"))?;
        if left == 0 {
            // The trailer, to its empty line; then no more is read.
            while !line(&mut body).await?.is_empty() {}
            let _ = to.shutdown().await;
            return Ok(());
        }
        while left > 0 {
            let want = (left as usize).min(READ);
            let n = body.read(&mut buf[..want]).await.map_err(|e| format!("client read failed: {e}"))?;
            if n == 0 {
                return Err("the client cut its body".into());
            }
            left -= n as u64;
            let take = moved.take(n, cap);
            to.write_all(&buf[..take]).await.map_err(|e| format!("write failed: {e}"))?;
            meter.up(take);
            if take < n {
                return Err("session byte cap".into());
            }
        }
        let mut crlf = [0u8; 2];
        body.read_exact(&mut crlf).await.map_err(|_| "the client cut its body".to_string())?;
        if &crlf != b"\r\n" {
            return Err("no CRLF after a chunk".into());
        }
    }
}

/// The target's bytes to the client in chunks as they come, each flushed;
/// the target's end is the last chunk. Ends with why the session ended.
async fn down<R, W>(
    mut from: R,
    mut to: W,
    meter: Arc<crate::serve::usage::Meter>,
    moved: Arc<Moved>,
    cap: u64,
) -> String
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) => {
                let _ = to.write_all(b"0\r\n\r\n").await;
                let _ = to.flush().await;
                let _ = to.shutdown().await;
                return "the target ended".into();
            }
            Ok(n) => n,
            Err(e) => return format!("target read failed: {e}"),
        };
        let take = moved.take(n, cap);
        if to.write_all(&chunk(&buf[..take])).await.is_err() || to.flush().await.is_err() {
            return "the client is gone".into();
        }
        meter.down(take);
        if take < n {
            return "session byte cap".into();
        }
    }
}

/// The session's limits, as a session of the split form has them; ends
/// with the one that was met.
async fn limits(moved: &Moved, cfg: &Config) -> String {
    let started = Instant::now();
    loop {
        tokio::time::sleep(TICK).await;
        let heard = moved.heard.lock().map(|h| *h).unwrap_or(started);
        if heard.elapsed() >= cfg.limits.idle {
            return "idle timeout".into();
        }
        if started.elapsed() >= cfg.limits.session {
            return "session time cap".into();
        }
    }
}

/// One line of the body's framing, without its CRLF; a longer line than
/// [`LINE_MAX`], or the body's end in it, is an error.
async fn line<R: AsyncRead + Unpin>(body: &mut BufReader<R>) -> Result<String, String> {
    let mut out = Vec::new();
    let mut limited = (&mut *body).take(LINE_MAX as u64 + 2);
    let n = limited.read_until(b'\n', &mut out).await.map_err(|e| format!("client read failed: {e}"))?;
    if n == 0 || !out.ends_with(b"\n") {
        return Err("the client cut its body".into());
    }
    out.pop();
    if out.last() == Some(&b'\r') {
        out.pop();
    }
    String::from_utf8(out).map_err(|_| "a chunk's line that is no text".into())
}

/// One chunk of a body in chunks: its size in hex, its bytes, CRLF.
fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_body_in_chunks_reaches_the_target_whole_and_its_end_is_the_half_close() {
        let wire = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n".to_vec();
        let (mut far, near) = tokio::io::duplex(1 << 16);
        let moved = Arc::new(Moved { bytes: AtomicU64::new(0), heard: Mutex::new(Instant::now()) });
        let meter = Arc::new(crate::serve::usage::Usage::default().meter("", false).unwrap());
        up(BufReader::new(&wire[..]), near, meter, moved.clone(), u64::MAX).await.unwrap();
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world", "the half-close ends the target's read");
        assert_eq!(moved.bytes.load(Ordering::SeqCst), 11);
    }

    #[tokio::test]
    async fn a_cut_body_or_a_broken_frame_is_an_error_and_the_cap_holds() {
        let meter = || Arc::new(crate::serve::usage::Usage::default().meter("", false).unwrap());
        let moved = || Arc::new(Moved { bytes: AtomicU64::new(0), heard: Mutex::new(Instant::now()) });
        for (wire, why) in [
            (&b"5\r\nhel"[..], "the client cut its body"),
            (b"zz\r\n", "a chunk's size \"zz\""),
            (b"2\r\nhiXX", "no CRLF after a chunk"),
        ] {
            let (_far, near) = tokio::io::duplex(1 << 16);
            let err = up(BufReader::new(wire), near, meter(), moved(), u64::MAX).await.unwrap_err();
            assert!(err.starts_with(why), "{err}");
        }
        let (_far, near) = tokio::io::duplex(1 << 16);
        let err =
            up(BufReader::new(&b"a\r\n0123456789\r\n0\r\n\r\n"[..]), near, meter(), moved(), 4).await.unwrap_err();
        assert_eq!(err, "session byte cap");
    }

    #[tokio::test]
    async fn the_target_s_bytes_go_down_in_chunks_and_its_end_is_the_last_chunk() {
        let moved = Arc::new(Moved { bytes: AtomicU64::new(0), heard: Mutex::new(Instant::now()) });
        let meter = Arc::new(crate::serve::usage::Usage::default().meter("", false).unwrap());
        let mut out = Vec::new();
        let why = down(&b"abc"[..], &mut out, meter, moved, u64::MAX).await;
        assert_eq!(why, "the target ended");
        assert_eq!(out, b"3\r\nabc\r\n0\r\n\r\n");
    }

    #[test]
    fn the_form_s_path_and_its_mark_are_its_own() {
        assert!(serves("/v1/http/one/github.com/22") && !serves("/v1/http/open/github.com/22"));
        assert!(super::super::serves("/v1/http/one/github.com/22"), "under the road's prefix");
        assert_eq!(chunk(MARK), b"12\r\npodssh-http-one 1\n\r\n");
    }
}
