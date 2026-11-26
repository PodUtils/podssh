//! A destination that is there and is no regular file (T-1038): a
//! character or block device, a FIFO or a socket. A copy never renames a
//! file over one, as that would put a plain file in the place of the device
//! (`/dev/null`, as root). The bytes go into it, as OpenSSH's scp and sftp
//! write them: opened to write, with no temporary name, no cut, and no change
//! of its mode or its times. Nothing can be read back from it, so the check
//! is the source's digest against the bytes that went; and a copy that
//! breaks does not start again, as a FIFO's reader would get its first bytes
//! two times. A socket takes no file's bytes: it is refused (73).
//!
//! The one check of each writer of a local file is [`local`]: `cp`, `mv`,
//! `scp`, `sftp get` and `job fetch` (through the copy down), and
//! `--result-file`. The far side's is [`far`], on the attributes of a stat.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Sftp, Writes};
use podssh_ssh::Log;
use sha2::{Digest, Sha256};

use super::chunks;
use super::digest::Sum;
use super::link::Meter;
use super::pipe::Shape;
use super::rate;
use super::transfer::{self, Cause, Done, Failed, Side};
use crate::exitmap::Fault;

/// How a copy into a far device is checked: no far digest can be taken.
pub const NOT_READ_BACK: &str = "none: a device keeps no bytes to read back";

/// What a destination that is no regular file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Char,
    Block,
    Fifo,
    Socket,
}

impl Kind {
    /// The words of the kind, for a line.
    pub fn what(self) -> &'static str {
        match self {
            Kind::Char => "a character device",
            Kind::Block => "a block device",
            Kind::Fifo => "a FIFO",
            Kind::Socket => "a socket",
        }
    }

    /// The kind of a POSIX `st_mode`, as SFTP's permissions carry it: none
    /// for a regular file, a directory, a link, or a mode with no type.
    pub fn of_mode(mode: u32) -> Option<Kind> {
        match mode & 0o170_000 {
            0o020_000 => Some(Kind::Char),
            0o060_000 => Some(Kind::Block),
            0o010_000 => Some(Kind::Fifo),
            0o140_000 => Some(Kind::Socket),
            _ => None,
        }
    }
}

/// The kind of the local `target`, through a link as a write goes: none
/// when it is missing, a regular file or a directory.
pub fn local(target: &Path) -> Option<Kind> {
    let meta = std::fs::metadata(target).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let kind = meta.file_type();
        [
            (kind.is_char_device(), Kind::Char),
            (kind.is_block_device(), Kind::Block),
            (kind.is_fifo(), Kind::Fifo),
            (kind.is_socket(), Kind::Socket),
        ]
        .into_iter()
        .find_map(|(is, kind)| is.then_some(kind))
    }
    // Windows: a name such as NUL is a device, which no rename may take.
    #[cfg(not(unix))]
    {
        (!meta.is_file() && !meta.is_dir()).then_some(Kind::Char)
    }
}

/// The kind of a far destination from its stat (which follows a link):
/// none for a regular file, a directory, or no type in its attributes.
pub fn far(attrs: &FileAttributes) -> Option<Kind> {
    attrs.permissions.and_then(Kind::of_mode)
}

/// The refusal of a socket, which no write of a file reaches.
pub fn socket(target: &str) -> Failed {
    Failed::new(Fault::CantCreate, format!("{target}: a socket, which takes no file's bytes"))
}

/// The local `target` of `kind`, opened to write into: no new name, no
/// cut. A FIFO is opened with no wait: one that no process reads is said
/// at once, never waited on with no end.
pub fn open_local(target: &Path, kind: Kind) -> Result<File, Failed> {
    let shown = target.display().to_string();
    if kind == Kind::Socket {
        return Err(socket(&shown));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(target).map_err(|e| {
        // ENXIO: the FIFO's open with no wait found no reader.
        #[cfg(unix)]
        let unread = kind == Kind::Fifo && e.raw_os_error() == Some(libc::ENXIO);
        #[cfg(not(unix))]
        let unread = false;
        let why = match unread {
            true => "a FIFO that no process reads; start its reader first".to_string(),
            false => format!("{} ({})", podssh_ws::text::said(&e), kind.what()),
        };
        Failed::new(Fault::CantCreate, format!("{shown}: {why}"))
    })?;
    blocking(&file).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {}", podssh_ws::text::said(&e))))?;
    Ok(file)
}

/// The descriptor back to blocking writes: the open alone had no wait.
#[cfg(unix)]
fn blocking(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: F_GETFL and F_SETFL on a descriptor that `file` holds open.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above; only O_NONBLOCK changes.
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn blocking(_: &File) -> std::io::Result<()> {
    Ok(())
}

/// The end of the bytes into `file`: a block device's are on its disk; a
/// character device and a FIFO keep none to sync (fsync of `/dev/null`
/// fails).
pub fn ended(file: File, target: &Path, kind: Kind) -> Result<(), Failed> {
    if kind != Kind::Block {
        return Ok(());
    }
    let shown = target.display();
    file.sync_all().map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {}", podssh_ws::text::said(&e))))
}

/// The file done: written into `target`, which kept its name, its mode and
/// its times.
pub fn done(source: &str, target: &str, bytes: u64, sum: Sum, verified_by: String) -> Done {
    Done { source: source.into(), destination: target.into(), bytes, sum: Some(sum), verified_by, ..Done::default() }
}

/// The refusal of a move within one server onto `target`, which is `what`:
/// the server's rename would put the file in the device's place.
pub fn no_rename(target: &str, what: &str) -> Failed {
    Failed::new(Fault::CantCreate, format!("{target}: {what}, which a rename would replace; podssh cp writes into it"))
}

/// The refusal of a copy within one server (copy-data) into `target`, which
/// is `what`: its far digest cannot read the bytes back.
pub fn not_within(target: &str, what: &str) -> Failed {
    let why = "a copy within one server writes into no device; copy the file here first, then up";
    Failed::new(Fault::CantCreate, format!("{target}: {what}; {why}"))
}

/// The words of a far file that the copy by exec finds to be no regular
/// file and no directory: its `test` tells no more.
pub const DEVICE_OR_FIFO: &str = "a device or a FIFO";

/// A failure of a copy into `target`, which is `what` ([`Kind::what`]): one
/// that broke is not continued, as its first bytes went already (a FIFO's
/// reader has them).
pub fn failed(mut failed: Failed, target: &str, what: &str) -> Failed {
    if matches!(failed.cause, Cause::Broke | Cause::Spent) {
        failed.cause = Cause::Answer;
        failed.message.push_str(&format!("; {target} is {what}, so the copy into it does not start again"));
    }
    failed
}

/// A copy up into the far `target` of `kind` (T-1038): opened to write
/// with no create and no cut, the bytes in order, closed. No temporary
/// name, no rename, no mode or times set, and no fsync, which a FIFO and
/// `/dev/null` refuse; the source's digest is of the bytes that went.
#[allow(clippy::too_many_arguments)]
pub async fn up_far(
    sftp: &Sftp,
    local: &Path,
    source: &str,
    target: &str,
    before: &std::fs::Metadata,
    kind: Kind,
    meter: &Meter,
    shape: Shape,
    log: &Log,
) -> Result<Done, Failed> {
    if kind == Kind::Socket {
        return Err(socket(target));
    }
    log.verbose(&format!("{source}: writing into {target} itself: it is {}", kind.what()));
    let no_input = |e: std::io::Error| Failed::new(Fault::NoInput, format!("{source}: {}", podssh_ws::text::said(&e)));
    let file = sftp
        .open_file(target, OpenFlags::WRITE, FileAttributes::default())
        .await
        .map_err(|e| failed(transfer::from_sftp(e, Side::Destination), target, kind.what()))?;
    let sent = async {
        let mut reader = File::open(local).map_err(no_input)?;
        let mut hasher = Sha256::new();
        let mut writes = Writes::new(sftp, &file, 0, rate::shaped(shape.pipe, sftp.write_len()));
        let mut buf = vec![0u8; writes.block() as usize];
        let mut offset = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(no_input)?;
            if n == 0 {
                break;
            }
            if offset + n as u64 > before.len() {
                return Err(transfer::changed(source));
            }
            if let Some(spent) = meter.spent(n as u64 + u64::from(chunks::RELAY_ROOM)) {
                return Err(spent);
            }
            hasher.update(&buf[..n]);
            rate::take(n as u64).await;
            writes.send(buf[..n].to_vec()).await.map_err(|e| refused(kind, target, e))?;
            offset += n as u64;
        }
        writes.finish().await.map_err(|e| refused(kind, target, e))?;
        Ok::<(u64, Sum), Failed>((offset, hasher.finalize().into()))
    }
    .await;
    let closed = sftp.close(&file).await;
    let (offset, sum) = sent.map_err(|f| failed(f, target, kind.what()))?;
    closed.map_err(|e| failed(transfer::from_sftp(e, Side::Destination), target, kind.what()))?;
    let after = std::fs::metadata(local).map_err(no_input)?;
    if after.len() != offset || after.modified().ok() != before.modified().ok() {
        return Err(transfer::changed(source));
    }
    Ok(done(source, target, offset, sum, NOT_READ_BACK.into()))
}

/// A write into the far `target` that the server refused. OpenSSH's
/// sftp-server seeks before each write, which a FIFO cannot do, so its
/// generic failure there is the FIFO's, not a full disk's.
fn refused(kind: Kind, target: &str, e: podssh_ssh::sftp::SftpError) -> Failed {
    match kind {
        Kind::Fifo => Failed::new(
            Fault::CantCreate,
            format!(
                "{target}: a FIFO on the server, which its SFTP server does not write into; the FIFO is left as it was"
            ),
        ),
        _ => transfer::write_failed(target, e),
    }
}

#[cfg(test)]
#[path = "special_tests.rs"]
mod tests;
