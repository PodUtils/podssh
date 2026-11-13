//! The `sftp` subsystem of `podssh serve` (T-112): SFTP version 3 as
//! OpenSSH's `sftp-server` speaks it, in the process, so that a cage with
//! no `sftp-server`, `scp` or `rsync` still moves files with OpenSSH's
//! `sftp`, `scp` (SFTP is its mode since OpenSSH 9.0) and `podssh cp`.
//!
//! The files are reached as the user that runs serve, with no chroot (a
//! cage has none): what that user may read and write, a client may. A
//! relative path starts at `HOME`, as `sftp-server` starts there.
//!
//! **Each wait has a limit.** Each file-system call runs on the session's
//! own thread within [`CALL_LIMIT`]; past it the reply is a failure with
//! the reason, the handle that it used is closed, and the session goes on
//! (a FIFO with no writer, or a dead mount, must not stop it). At most
//! [`MAX_HANDLES`] handles are open, a read is [`MAX_READ`] at most, and a
//! request is [`MAX_PACKET`] at most: the memory of a session is bounded.
//!
//! **The wire is russh-sftp's** (its packets and their codec, the crate of
//! podssh's own client, T-133); the loop is this module's, as the crate's
//! own server loop goes on after a read that failed and never closes the
//! channel. Requests are answered one at a time, in their order, as
//! `sftp-server` answers them.

mod answer;
mod fs;
mod worker;

#[cfg(test)]
mod tests;

pub use fs::NAMES_PER_READ;
pub use worker::MAX_STUCK;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use russh_sftp::protocol::{Packet, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::channel::Open;
use super::{env, Settings};
use answer::{status, Session};
use worker::Worker;

/// The limit of each file-system call.
pub const CALL_LIMIT: Duration = Duration::from_secs(20);
/// The most handles open at once in a session.
pub const MAX_HANDLES: usize = 256;
/// The longest request, as `sftp-server`'s `SFTP_MAX_MSG_LENGTH`.
pub const MAX_PACKET: u32 = 256 * 1024;
/// The longest read, and the longest write that `limits@openssh.com` names:
/// a reply of it stays within [`MAX_PACKET`].
pub const MAX_READ: u32 = MAX_PACKET - 1024;
/// The bytes from the channel that wait for the server at most.
const PIPE: usize = 1 << 20;

/// A rename over an existing name, as rename(2) does (T-134 needs it).
pub const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// A file's data to the disk before its rename (T-134).
pub const FSYNC: &str = "fsync@openssh.com";
/// The limits above, so that a client sends reads and writes of their size.
pub const LIMITS: &str = "limits@openssh.com";
/// The extensions of the version reply, with their versions.
pub const EXTENSIONS: &[(&str, &str)] = &[(POSIX_RENAME, "1"), (FSYNC, "1"), (LIMITS, "1")];

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_EXTENDED: u8 = 200;

/// Serve SFTP on the session channel `open`: its data becomes the server's
/// input, and the replies its data, until the client's EOF or close. `Err`
/// is the line for the client when it cannot start.
pub(in crate::server) fn start(open: &mut Open, settings: &Settings) -> Result<(), String> {
    let Some(write) = open.write.take() else {
        return Err("a program or a subsystem runs on this channel already".into());
    };
    let (to_server, from_client) = tokio::io::duplex(PIPE);
    open.give_input(Box::new(to_server));
    let home = env::workdir(&settings.base());
    let limit = settings.sftp_limit.unwrap_or(CALL_LIMIT);
    let mut closed = open.closed.clone();
    tokio::spawn(async move {
        let ended = tokio::select! {
            ended = serve(from_client, write.make_writer(), home, limit) => ended,
            // A client that closed the channel reads nothing more.
            () = super::child::turned(&mut closed) => return,
        };
        // The reason goes where sftp-server's own log line goes over sshd:
        // the channel's stderr.
        if let Err(why) = &ended {
            let line = format!("podssh serve: sftp: {why}\n");
            let _ = write.make_writer_ext(Some(1)).write_all(line.as_bytes()).await;
        }
        // The status that sshd sends when sftp-server exits: a client that
        // has none says -1, and OpenSSH's scp then exits 1 after a copy.
        let _ = write.exit_status(u32::from(ended.is_err())).await;
        let _ = write.eof().await;
        let _ = write.close().await;
    });
    Ok(())
}

/// One packet's body (its type and its fields), or None at the end of the
/// input between two packets.
async fn read_packet<R: AsyncRead + Unpin>(input: &mut R) -> Result<Option<Bytes>, String> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("the channel failed: {e}")),
    }
    let len = u32::from_be_bytes(len);
    // A length past the limit leaves no packet boundary to read on from.
    if len == 0 || len > MAX_PACKET {
        return Err(format!("a packet of {len} bytes, where {MAX_PACKET} is the most"));
    }
    let mut body = vec![0u8; len as usize];
    input.read_exact(&mut body).await.map_err(|e| format!("the input ended inside a packet: {e}"))?;
    Ok(Some(Bytes::from(body)))
}

/// A packet with its length.
fn encode(packet: Packet) -> Result<Bytes, String> {
    Bytes::try_from(packet).map_err(|e| format!("a reply did not encode: {e}"))
}

/// The version reply: version 3, whatever the client asked, as
/// `sftp-server` answers, with the extensions served.
fn version() -> Packet {
    let extensions: HashMap<String, String> =
        EXTENSIONS.iter().map(|(name, v)| (name.to_string(), v.to_string())).collect();
    Packet::Version(Version { version: 3, extensions })
}

/// Whether `kind` is a request that a client may send.
fn is_request(kind: u8) -> bool {
    kind == SSH_FXP_INIT || (3..=20).contains(&kind) || kind == SSH_FXP_EXTENDED
}

/// Serve SFTP on `input` and `output` until the input ends. `home` is where
/// a relative path starts; `limit` bounds each file-system call. `Err` is
/// why the session ended early: a packet that breaks the protocol, a
/// channel that failed, or [`MAX_STUCK`] calls left.
pub async fn serve<R, W>(mut input: R, mut output: W, home: PathBuf, limit: Duration) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut session: Option<Session> = None;
    while let Some(mut body) = read_packet(&mut input).await? {
        let kind = body[0];
        // The id follows the type in each request but INIT.
        let id = body.get(1..5).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        let reply = match session.as_mut() {
            // As sftp-server: the first packet is INIT, and there is one.
            None if kind != SSH_FXP_INIT => {
                return Err(format!("the first packet is of type {kind}, and SSH_FXP_INIT comes first"))
            }
            None => None,
            Some(_) if kind == SSH_FXP_INIT => return Err("a second SSH_FXP_INIT".into()),
            Some(_) if !is_request(kind) => {
                Some(status(id, StatusCode::OpUnsupported, format!("the packet type {kind} is no request served here")))
            }
            Some(open) => Some(match Packet::try_from(&mut body) {
                Ok(packet) => open.answer(packet).await,
                Err(e) => {
                    status(id, StatusCode::BadMessage, format!("a packet of type {kind} that does not parse: {e}"))
                }
            }),
        };
        let reply = reply.unwrap_or_else(|| {
            session = Some(Session::new(home.clone(), Worker::new(limit)));
            version()
        });
        let bytes = encode(reply)?;
        output.write_all(&bytes).await.map_err(|e| format!("the reply could not be sent: {e}"))?;
        output.flush().await.map_err(|e| format!("the reply could not be sent: {e}"))?;
        if session.as_ref().is_some_and(|s| s.stuck() >= MAX_STUCK) {
            return Err(format!("{MAX_STUCK} file-system calls gave no answer: the session ends"));
        }
    }
    Ok(())
}
