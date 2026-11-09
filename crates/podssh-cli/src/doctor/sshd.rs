//! The line `sshd` (T-590): whether this host has the sshd that a roost
//! (`podssh node --sshd`) serves, and what one dial of the roost's default
//! TARGET reads first, judged as the roost judges it. A note: a host with no
//! roost needs no sshd, so each form is ok, and never a failure.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use podssh_relay::reverse::sshd::{judge, unjudged, End, NotSshd, READ_MAX};

use super::Report;
use crate::local_sshd::{self, Found};

/// The bound on the dial and the first line together.
const LIMIT: Duration = Duration::from_secs(2);

/// What one dial of the roost's TARGET gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Port {
    /// Its first line, an SSH version line.
    Answers(String),
    /// The dial was refused: nothing listens.
    Refused,
    /// The dial had no answer within the bound.
    NoAnswer,
    /// It answered, and not as sshd.
    Not(NotSshd),
}

pub(super) fn check(report: &mut Report<'_>) {
    let places = local_sshd::places();
    let found = local_sshd::look(std::env::var_os("PATH"), &places);
    let target = crate::node::SSHD;
    let port = match target.parse::<SocketAddr>() {
        Ok(addr) => dial(addr),
        Err(e) => Port::Not(NotSshd::Failed(e.to_string())),
    };
    report.ok("sshd", words(&found, &places, target, &port));
}

/// One dial of `addr`, and its first line within [`LIMIT`].
fn dial(addr: SocketAddr) -> Port {
    let deadline = Instant::now() + LIMIT;
    let mut stream = match TcpStream::connect_timeout(&addr, LIMIT) {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Port::Refused,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Port::NoAnswer,
        Err(e) => return Port::Not(NotSshd::Failed(e.to_string())),
    };
    let read = |buf: &mut [u8], left: Duration| {
        stream.set_read_timeout(Some(left))?;
        stream.read(buf)
    };
    match first_line(read, deadline) {
        Ok(line) => Port::Answers(line),
        Err(why) => Port::Not(why),
    }
}

/// The version line that `read` gives before `deadline`, judged by the
/// roost's own rule, which skips the lines before it (T-702). `read` takes
/// the time left, which is never zero, and no more than the rule reads.
fn first_line(
    mut read: impl FnMut(&mut [u8], Duration) -> std::io::Result<usize>,
    deadline: Instant,
) -> Result<String, NotSshd> {
    let mut bytes = Vec::new();
    let mut buf = vec![0u8; READ_MAX];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(unjudged(&bytes, End::Limit(LIMIT)));
        }
        // `judge` decides by READ_MAX bytes, so the room is never zero here.
        let room = READ_MAX.saturating_sub(bytes.len()).max(1);
        match read(&mut buf[..room], left) {
            Ok(0) => return Err(unjudged(&bytes, End::Closed)),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if let Some(verdict) = judge(&bytes) {
                    return verdict;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(unjudged(&bytes, End::Limit(LIMIT)));
            }
            Err(e) => return Err(NotSshd::Failed(e.to_string())),
        }
    }
}

/// The line: where sshd is, what `target` answered, and what a roost needs
/// when it is not there or not running.
fn words(found: &Found, places: &[PathBuf], target: &str, port: &Port) -> String {
    let what = match found {
        Found::At(at) => format!("present at {}", at.display()),
        Found::Absent(_) => format!("absent ({})", local_sshd::searched(places)),
    };
    let answer = match port {
        Port::Answers(line) => format!("{target} answers {line}"),
        Port::Refused => format!("nothing listens at {target}"),
        Port::NoAnswer => format!("{target} did not answer the dial within {} s", LIMIT.as_secs()),
        Port::Not(why) => format!("{target} is not an sshd: it {why}"),
    };
    let roost = "a roost (podssh node --sshd)";
    let next = match (found, port) {
        // A roost with no TARGET serves it.
        (_, Port::Answers(_)) => String::new(),
        (Found::At(_), _) => format!("; {roost} needs it started there, or a TARGET at the port that it listens on"),
        (Found::Absent(Some(command)), _) => format!("; {roost} needs one: {command}"),
        (Found::Absent(None), _) => format!("; {roost} needs one, and no package manager was found on PATH"),
    };
    format!("{what}; {answer}{next}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that gives `chunks` in turn, then waits out its time.
    fn chunks(mut chunks: Vec<&'static [u8]>) -> impl FnMut(&mut [u8], Duration) -> std::io::Result<usize> {
        chunks.reverse();
        move |buf: &mut [u8], _left: Duration| match chunks.pop() {
            Some(chunk) => {
                buf[..chunk.len()].copy_from_slice(chunk);
                Ok(chunk.len())
            }
            None => Err(std::io::ErrorKind::TimedOut.into()),
        }
    }

    fn read(parts: Vec<&'static [u8]>) -> Result<String, NotSshd> {
        first_line(chunks(parts), Instant::now() + LIMIT)
    }

    #[test]
    fn the_first_line_is_judged_as_the_roost_judges_it() {
        assert_eq!(read(vec![&b"SSH-2.0-OpenSSH_9.6\r\n"[..]]), Ok("SSH-2.0-OpenSSH_9.6".into()));
        let parts = vec![&b"SSH-2.0-"[..], &b"dropbear_2024.86\r\n"[..]];
        assert_eq!(read(parts), Ok("SSH-2.0-dropbear_2024.86".into()));
        let http = read(vec![&b"HTTP/1.1 400 Bad Request\r\n"[..]]);
        assert_eq!(http, Err(NotSshd::Other("HTTP/1.1 400 Bad Request".into())));
        assert_eq!(read(vec![]), Err(NotSshd::Silent { after: LIMIT, seen: String::new() }));
        assert_eq!(read(vec![&b"SSH-2.0"[..]]), Err(NotSshd::Silent { after: LIMIT, seen: "SSH-2.0".into() }));
        assert_eq!(read(vec![&b""[..]]), Err(NotSshd::Closed));
    }

    /// The inputs of T-702 for the doctor's line: the lines before the
    /// version line, and a first piece shorter than `SSH-`, pass here as on
    /// the direct road; an HTTP answer whose server closes is named.
    #[test]
    fn a_greeting_or_a_short_first_piece_passes_as_on_the_direct_road() {
        assert_eq!(read(vec![&b"SS"[..], &b"H-2.0-OpenSSH_9.6\r\n"[..]]), Ok("SSH-2.0-OpenSSH_9.6".into()));
        let greeting = vec![&b"Welcome to the lab\r\nSSH-2.0-OpenSSH_9.6\r\n"[..]];
        assert_eq!(read(greeting), Ok("SSH-2.0-OpenSSH_9.6".into()));
        let alone = vec![&b"Welcome to the lab\r\n"[..], &b"SSH-2.0-OpenSSH_9.6\r\n"[..]];
        assert_eq!(read(alone), Ok("SSH-2.0-OpenSSH_9.6".into()));
        let closed = read(vec![&b"HTTP/1.1 400 Bad Request\r\n"[..], &b""[..]]);
        assert_eq!(closed, Err(NotSshd::Other("HTTP/1.1 400 Bad Request".into())));
    }

    #[test]
    fn the_three_forms_of_the_line() {
        let places = [PathBuf::from("/usr/sbin"), PathBuf::from("/sbin")];
        let at = Found::At("/usr/sbin/sshd".into());
        let target = "127.0.0.1:22";
        let answers = words(&at, &places, target, &Port::Answers("SSH-2.0-OpenSSH_9.6".into()));
        assert_eq!(answers, "present at /usr/sbin/sshd; 127.0.0.1:22 answers SSH-2.0-OpenSSH_9.6");
        let stopped = words(&at, &places, target, &Port::Refused);
        assert_eq!(
            stopped,
            "present at /usr/sbin/sshd; nothing listens at 127.0.0.1:22; a roost (podssh node --sshd) needs it \
             started there, or a TARGET at the port that it listens on"
        );
        let absent = Found::Absent(Some("apt-get install -y openssh-server".into()));
        assert_eq!(
            words(&absent, &places, target, &Port::Refused),
            "absent (none on PATH or in /usr/sbin, /sbin); nothing listens at 127.0.0.1:22; a roost (podssh node \
             --sshd) needs one: apt-get install -y openssh-server"
        );
        // Another server of SSH at the port, as Dropbear, is what a roost
        // serves, with no sshd found.
        let other = words(&absent, &places, target, &Port::Answers("SSH-2.0-dropbear_2024.86".into()));
        assert_eq!(
            other,
            "absent (none on PATH or in /usr/sbin, /sbin); 127.0.0.1:22 answers SSH-2.0-dropbear_2024.86"
        );
        let http = words(&at, &places, target, &Port::Not(NotSshd::Other("HTTP/1.1 400 Bad Request".into())));
        assert!(http.contains("127.0.0.1:22 is not an sshd: it sent \"HTTP/1.1 400 Bad Request\" first"), "{http}");
    }
}
