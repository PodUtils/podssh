//! The HTTP/1.1 of the stand-ins: a request's head and its body by
//! `Content-Length` (the road sends no chunked body, so one is refused as a
//! request that does not read), an answer with `Connection: close`, and the
//! parts of a `multipart/form-data` body (RFC 7578) as a host reads them.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The most bytes of a head, and of a body: a piece is 4 MiB at most.
const HEAD_MOST: usize = 64 << 10;
const BODY_MOST: usize = 8 << 20;

/// One request.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Each header, its name in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
    }

    /// The host that the request names, in lower case, with no port.
    pub fn host(&self) -> String {
        let host = self.header("host").unwrap_or_default();
        host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h).to_ascii_lowercase()
    }

    /// The boundary of a `multipart/form-data` body.
    pub fn boundary(&self) -> Option<String> {
        let kind = self.header("content-type")?;
        let (form, rest) = kind.split_once(';')?;
        if !form.trim().eq_ignore_ascii_case("multipart/form-data") {
            return None;
        }
        let at = rest.find("boundary=")?;
        Some(rest[at + "boundary=".len()..].trim().trim_matches('"').to_string())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A connection's head, up to its blank line, and the bytes read past it.
pub async fn head<S: AsyncRead + Unpin>(io: &mut S) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(at + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() > HEAD_MOST {
            return Err(std::io::Error::other("a head over 64 KiB"));
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The request on `io`; `None` for a connection closed before a byte.
pub async fn read<S: AsyncRead + Unpin>(io: &mut S) -> std::io::Result<Option<Request>> {
    let (text, mut body) = match head(io).await {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let (method, path) = (first.next().unwrap_or_default().to_string(), first.next().unwrap_or("/").to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    if header("transfer-encoding").is_some() {
        return Err(std::io::Error::other("a chunked body, which the road does not send"));
    }
    let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if length > BODY_MOST {
        return Err(std::io::Error::other("a body over 8 MiB"));
    }
    let mut chunk = vec![0u8; 64 * 1024];
    while body.len() < length {
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::other(format!("a body of {} bytes of {length}", body.len())));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(Some(Request { method, path, headers, body }))
}

/// The answer `status` with `headers` and `body`, then the close.
pub async fn write<S: AsyncWrite + Unpin>(
    io: &mut S,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Other",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    io.write_all(head.as_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    io.shutdown().await
}

/// The value of `key="..."` in a part's disposition.
fn attribute(head: &str, key: &str) -> Option<String> {
    let mark = format!("; {key}=\"");
    let at = head.find(&mark)? + mark.len();
    let end = head[at..].find('"')?;
    Some(head[at..at + end].to_string())
}

/// The parts of a form: each one's name, its file name for a file, and its
/// bytes. A part that does not read ends the list.
pub fn parts(body: &[u8], boundary: &str) -> Vec<(String, Option<String>, Vec<u8>)> {
    let mark = format!("--{boundary}").into_bytes();
    let next = [b"\r\n".as_slice(), &mark].concat();
    let mut out = Vec::new();
    let Some(first) = find(body, &mark) else { return out };
    let mut at = first + mark.len();
    loop {
        let rest = &body[at..];
        // `--` after a boundary ends the form.
        let Some(rest) = rest.strip_prefix(b"\r\n") else { return out };
        let Some(head_end) = find(rest, b"\r\n\r\n") else { return out };
        let head = String::from_utf8_lossy(&rest[..head_end]).into_owned();
        let content = &rest[head_end + 4..];
        let Some(end) = find(content, &next) else { return out };
        let Some(name) = attribute(&head, "name") else { return out };
        out.push((name, attribute(&head, "filename"), content[..end].to_vec()));
        // Past this part's bytes and the next boundary.
        at += 2 + head_end + 4 + end + next.len();
    }
}
