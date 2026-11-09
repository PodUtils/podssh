//! The one rule for "this peer is an SSH server" (T-702), and the check of a
//! roost (T-166): a node in front of a standard sshd. RFC 4253 (section 4.2)
//! lets a server send other lines before its version line, and no such line
//! starts with `SSH-`: the verdict comes from the first line that does,
//! within [`READ_MAX`] bytes. [`judge`] is that rule for each reader that
//! asks it: the roost here, the direct road and the probes of `doctor` in
//! podssh-cli. The roost's check peeks at the bytes and takes none of them:
//! the session's SSH client still reads the line itself.
//!
//! The four-byte sniff of the relay role's shared port
//! (`crate::serve::sshd::judge`) is no judge of a server: it reads a
//! client's first bytes to choose a road, and stays apart.

use std::fmt;
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::TcpStream;

/// How long sshd may take to send its version line.
pub const BANNER_LIMIT: Duration = Duration::from_secs(10);
/// The most bytes that a verdict reads: a version line is 255 bytes at most,
/// and the lines before it are bounded by these 4 KiB, as the direct road's
/// one read was (T-363).
pub const READ_MAX: usize = 4096;
/// How long a peek that saw part of a line waits before it looks again: the
/// bytes stay in the stream, so a peek at once would see the same.
const PEEK_AGAIN: Duration = Duration::from_millis(20);
/// The most of a line that a message shows.
const SHOWN: usize = 80;
/// The start of a version line, and of no other line of a server.
const START: &[u8] = b"SSH-";
/// The starts of a version line of SSH 2: `SSH-1.99-` is a server that also
/// speaks SSH 1, which RFC 4253 (section 5.1) lets an SSH 2 client use.
const VERSIONS: [&[u8]; 2] = [b"SSH-2.0-", b"SSH-1.99-"];

/// Why a TARGET is not a standard sshd. Each says what came back, after
/// "it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSshd {
    /// No version line came after its first line: another service.
    Other(String),
    /// Its version line is not one of SSH 2.
    Version(String),
    /// No verdict within the limit, and the part of a version line that
    /// came, if any.
    Silent { after: Duration, seen: String },
    /// It closed the connection before its version line.
    Closed,
    /// The connection failed before its version line.
    Failed(String),
}

impl NotSshd {
    /// Whether another service answered: no wait mends that, as TARGET is
    /// set up wrong.
    pub fn is_other(&self) -> bool {
        matches!(self, NotSshd::Other(_) | NotSshd::Version(_))
    }
}

impl fmt::Display for NotSshd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotSshd::Other(line) => write!(f, "sent {line:?} first, and no version line SSH-2.0-..."),
            NotSshd::Version(line) => write!(f, "sent the version line {line:?}, not one of SSH 2 (SSH-2.0-...)"),
            NotSshd::Silent { after, seen } if seen.is_empty() => {
                write!(f, "sent no line within {} s", after.as_secs())
            }
            NotSshd::Silent { after, seen } => {
                write!(f, "sent {seen:?} and no whole line within {} s", after.as_secs())
            }
            NotSshd::Closed => write!(f, "closed the connection before its version line"),
            NotSshd::Failed(why) => write!(f, "failed before its version line: {why}"),
        }
    }
}

impl std::error::Error for NotSshd {}

/// How the bytes of a peer stopped before [`judge`] gave a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The limit ended, with the peer still open.
    Limit(Duration),
    /// The peer closed the connection.
    Closed,
}

/// The version line of the sshd at the other end of `stream`, within
/// `limit`. Each byte stays in the stream for the session.
pub async fn check(stream: &TcpStream, limit: Duration) -> Result<String, NotSshd> {
    let mut seen = Vec::new();
    let result = tokio::time::timeout(limit, version_line(stream, &mut seen)).await;
    match result {
        Ok(verdict) => verdict,
        Err(_) => Err(unjudged(&seen, End::Limit(limit))),
    }
}

/// The roost peeks, where the direct road reads: its stream is the
/// `TcpStream` that each handler hands on to the session, and a peek leaves
/// sshd's line in it. A proxy's stream offers no peek, so the readers of
/// podssh-cli read and give the bytes back (T-363).
async fn version_line(stream: &TcpStream, seen: &mut Vec<u8>) -> Result<String, NotSshd> {
    let mut buf = vec![0u8; READ_MAX];
    loop {
        let n = stream.peek(&mut buf).await.map_err(|e| NotSshd::Failed(e.to_string()))?;
        if n == 0 {
            return Err(NotSshd::Closed);
        }
        seen.clear();
        seen.extend_from_slice(&buf[..n]);
        if let Some(verdict) = judge(seen) {
            return verdict;
        }
        // After the peer's close, a peek sees the same bytes again, never the
        // 0 of a read: the readiness says that it closed, so a service that
        // closes after its lines is refused at once, not at the limit. One
        // more peek takes what came with the close.
        let closed = stream.ready(Interest::READABLE).await.is_ok_and(|r| r.is_read_closed());
        if closed {
            let n = stream.peek(&mut buf).await.map_err(|e| NotSshd::Failed(e.to_string()))?;
            seen.clear();
            seen.extend_from_slice(&buf[..n]);
            return judge(seen).unwrap_or_else(|| Err(unjudged(seen, End::Closed)));
        }
        tokio::time::sleep(PEEK_AGAIN).await;
    }
}

/// The verdict on the first bytes of a peer, once they decide it: the first
/// line that starts with `SSH-` (each line before it is skipped, as RFC 4253
/// lets a server send them), a byte that no line of text has, or
/// [`READ_MAX`] bytes with no version line. `None`: wait for more.
pub fn judge(bytes: &[u8]) -> Option<Result<String, NotSshd>> {
    let bytes = &bytes[..bytes.len().min(READ_MAX)];
    let mut rest = bytes;
    while let Some(end) = rest.iter().position(|b| *b == b'\n') {
        let line = without_cr(&rest[..end]);
        if line.starts_with(START) {
            return Some(version(line));
        }
        if line.iter().copied().any(binary) {
            return Some(Err(other(bytes)));
        }
        rest = &rest[end + 1..];
    }
    // `rest` is a line that has not ended yet.
    if rest.starts_with(START) {
        if !VERSIONS.iter().any(|v| v.starts_with(rest) || rest.starts_with(v)) {
            return Some(Err(NotSshd::Version(shown(without_cr(rest)))));
        }
    } else if rest.iter().copied().any(binary) {
        return Some(Err(other(bytes)));
    }
    (bytes.len() >= READ_MAX).then(|| Err(other(bytes)))
}

/// What `bytes` say when no more came (`end`) and [`judge`] gave no
/// verdict: a part of a version line, or nothing, is a silence or a close;
/// lines with no version line among them are another service.
pub fn unjudged(bytes: &[u8], end: End) -> NotSshd {
    let rest = bytes.rsplit(|b| *b == b'\n').next().unwrap_or(bytes);
    let version_begun = !rest.is_empty() && (START.starts_with(rest) || rest.starts_with(START));
    if bytes.is_empty() || version_begun {
        let seen = if version_begun { shown(without_cr(rest)) } else { String::new() };
        return match end {
            End::Limit(after) => NotSshd::Silent { after, seen },
            End::Closed => NotSshd::Closed,
        };
    }
    other(bytes)
}

/// The verdict on a whole line that starts with `SSH-`.
fn version(line: &[u8]) -> Result<String, NotSshd> {
    if VERSIONS.iter().any(|v| line.starts_with(v)) {
        Ok(shown(line))
    } else {
        Err(NotSshd::Version(shown(line)))
    }
}

/// Another service, named by its first line.
fn other(bytes: &[u8]) -> NotSshd {
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or(bytes);
    NotSshd::Other(shown(without_cr(first)))
}

/// A byte that no line of text has: a binary protocol, such as a record of
/// TLS (0x15, 0x16), decides at once. Tab, CR, LF and ESC (the colours of a
/// greeting) are text.
fn binary(b: u8) -> bool {
    (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n' | 0x1b)) || b == 0x7f
}

fn without_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// A line from a peer, safe to print, and short.
fn shown(line: &[u8]) -> String {
    podssh_ws::text::one_line(&String::from_utf8_lossy(line)).chars().take(SHOWN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_line_of_ssh_2_passes() {
        assert_eq!(judge(b"SSH-2.0-OpenSSH_9.6\r\n"), Some(Ok("SSH-2.0-OpenSSH_9.6".into())));
        assert_eq!(judge(b"SSH-2.0-dropbear_2024.86\n"), Some(Ok("SSH-2.0-dropbear_2024.86".into())));
        assert_eq!(judge(b"SSH-1.99-Cisco-1.25\r\nmore"), Some(Ok("SSH-1.99-Cisco-1.25".into())));
    }

    /// RFC 4253, section 4.2: lines before the version line are skipped,
    /// in one write or in several.
    #[test]
    fn a_greeting_before_the_version_line_passes() {
        let one_write = b"Welcome to the lab\r\n\x1b[1mauthorised use only\x1b[0m\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n";
        assert_eq!(judge(one_write), Some(Ok("SSH-2.0-OpenSSH_9.6".into())));
        assert_eq!(judge(b"Welcome to the lab\r\n"), None, "a greeting alone waits");
        assert_eq!(judge(b"Welcome to the lab\r\nSS"), None);
        assert_eq!(judge(b"Welcome\r\nSSH-1.5-old\r\n"), Some(Err(NotSshd::Version("SSH-1.5-old".into()))));
    }

    #[test]
    fn another_service_is_named_by_its_first_line() {
        let http = judge(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(http, None, "lines of text may be a greeting: the end or the limit decides");
        let ended = unjudged(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", End::Closed);
        assert_eq!(ended, NotSshd::Other("HTTP/1.1 400 Bad Request".into()));
        let alone = unjudged(b"HTTP/1.1 400 Bad Request", End::Limit(BANNER_LIMIT));
        assert_eq!(alone, NotSshd::Other("HTTP/1.1 400 Bad Request".into()));
        assert_eq!(judge(b"SSH-1.5-old\r\n"), Some(Err(NotSshd::Version("SSH-1.5-old".into()))));
        assert_eq!(judge(b"SSH-2.0\r\n"), Some(Err(NotSshd::Version("SSH-2.0".into()))));
        // A start of SSH that no version of SSH 2 has decides at once.
        assert_eq!(judge(b"SSH-1.5"), Some(Err(NotSshd::Version("SSH-1.5".into()))));
        // A record of TLS (an alert), which no line of text holds.
        assert!(matches!(judge(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]), Some(Err(NotSshd::Other(_)))));
        assert!(NotSshd::Version("SSH-1.5-old".into()).is_other());
    }

    #[test]
    fn part_of_a_version_line_waits_for_more() {
        for part in [&b"S"[..], b"SS", b"SSH-", b"SSH-2.0", b"SSH-2.0-OpenSSH", b"SSH-1.9", b"\x1b[2J"] {
            assert_eq!(judge(part), None, "{part:?}");
        }
        let limit = End::Limit(BANNER_LIMIT);
        assert_eq!(unjudged(b"SS", limit), NotSshd::Silent { after: BANNER_LIMIT, seen: "SS".into() });
        assert_eq!(unjudged(b"", limit), NotSshd::Silent { after: BANNER_LIMIT, seen: String::new() });
        assert_eq!(unjudged(b"SSH-2.0-Op", End::Closed), NotSshd::Closed);
    }

    /// 4 KiB of lines with no version line decide, as the direct road's
    /// one read of 4 KiB did (T-363).
    #[test]
    fn four_kib_with_no_version_line_decide() {
        let mut lines = Vec::new();
        while lines.len() < READ_MAX {
            lines.extend_from_slice(b"a line of a greeting\r\n");
        }
        assert_eq!(judge(&lines[..READ_MAX - 1]), None);
        assert_eq!(judge(&lines), Some(Err(NotSshd::Other("a line of a greeting".into()))));
        let mut late = lines[..READ_MAX - 4].to_vec();
        late.extend_from_slice(b"SSH-2.0-late\r\n");
        assert!(matches!(judge(&late), Some(Err(NotSshd::Other(_)))), "the version line must end within 4 KiB");
    }
}
