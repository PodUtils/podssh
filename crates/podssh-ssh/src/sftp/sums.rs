//! podssh's own SFTP requests between two podssh ends (T-150): the SHA-256
//! of a byte range of an open file, and the SHA-256 of each block of a
//! range. SFTP version 3 has neither, so against another server a copy
//! reads its file a second time or runs a digest tool (T-134).
//!
//! Both are `SSH_FXP_EXTENDED` requests under podssh's own names, listed in
//! the version reply of `podssh serve`; a client asks only a server that
//! lists them. Standard clients see a normal SFTP server. The wire format,
//! one codec for the client and the server, is in `docs/design.md`
//! (section "podssh's own SFTP requests").
//!
//! **Each reply has a limit that grows with the range**: the server reads
//! at the speed of its disk, so a range of 1 GiB cannot answer within the
//! limit of a stat. The floor of that speed is [`DISK_RATE`].
//!
//! **A reply names the state of the file that it read** (its size and time
//! of change after the read), so that a caller can tell a file that a write
//! changed since an earlier reply.

use std::io;
use std::time::Duration;

use russh_sftp::protocol::Packet;
use sha2::{Digest, Sha256};

use super::{within, FileHandle, Sftp, SftpError};

/// The request for the SHA-256 of a range.
pub const SHA256: &str = "sha256@podssh";
/// The request for the SHA-256 of each block of a range (T-142).
pub const SHA256_BLOCKS: &str = "sha256-blocks@podssh";
/// The smallest block that a client may ask for.
pub const MIN_BLOCK: u32 = 1024;
/// The largest block that a client may ask for.
pub const MAX_BLOCK: u32 = 64 << 20;
/// The most digests in one reply: 8,000 of 32 bytes stay within the
/// server's packet of 256 KiB with room for the header.
pub const MAX_BLOCKS: u64 = 8000;
/// The slowest disk that a limit allows for, in bytes each second.
pub const DISK_RATE: u64 = 32 << 20;
/// The bytes of a reply before its digests.
const HEAD: usize = 8 + 8 + 8 + 4 + 4;

/// A SHA-256.
pub type Sum = [u8; 32];

/// One request: the handle, where the range starts, its length (0: to the
/// end of the file as the server saw it first), and the block (0: one
/// digest of the whole range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub handle: String,
    pub offset: u64,
    pub len: u64,
    pub block: u32,
}

/// A reply: the file's size and time of change after the read, the bytes
/// hashed, the block (0 for one digest of the range) and the digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sums {
    pub size: u64,
    pub mtime: u64,
    pub hashed: u64,
    pub block: u32,
    pub sums: Vec<Sum>,
}

/// The limit of a reply for a range of `len` bytes: `base`, and one second
/// for each [`DISK_RATE`] bytes.
pub fn reply_limit(base: Duration, len: u64) -> Duration {
    base.saturating_add(Duration::from_secs(len / DISK_RATE))
}

/// The digests that a reply of `hashed` bytes in blocks of `block` carries.
pub fn blocks_of(hashed: u64, block: u32) -> u64 {
    if block == 0 {
        1
    } else {
        hashed.div_ceil(u64::from(block))
    }
}

/// The data of a request: string handle, uint64 offset, uint64 length, and
/// for [`SHA256_BLOCKS`] a uint32 block.
pub fn encode_request(asked: &Asked) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + asked.handle.len() + 20);
    out.extend_from_slice(&(asked.handle.len() as u32).to_be_bytes());
    out.extend_from_slice(asked.handle.as_bytes());
    out.extend_from_slice(&asked.offset.to_be_bytes());
    out.extend_from_slice(&asked.len.to_be_bytes());
    if asked.block != 0 {
        out.extend_from_slice(&asked.block.to_be_bytes());
    }
    out
}

/// A big-endian number of `N` bytes at `at`.
fn take<const N: usize>(data: &[u8], at: &mut usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    let bytes: [u8; N] = data.get(*at..end)?.try_into().ok()?;
    *at = end;
    Some(bytes)
}

/// A request's data, or why it does not parse: trailing bytes, a handle
/// that is not UTF-8, or a block out of range each refuse it.
pub fn parse_request(data: &[u8], blocks: bool) -> Result<Asked, String> {
    let short = || "its data is shorter than its fields".to_string();
    let mut at = 0;
    let len = u32::from_be_bytes(take::<4>(data, &mut at).ok_or_else(short)?) as usize;
    let end = at.checked_add(len).ok_or_else(short)?;
    let handle = data.get(at..end).ok_or_else(short)?;
    let handle = String::from_utf8(handle.to_vec()).map_err(|_| "its handle is not UTF-8".to_string())?;
    at = end;
    let offset = u64::from_be_bytes(take::<8>(data, &mut at).ok_or_else(short)?);
    let len = u64::from_be_bytes(take::<8>(data, &mut at).ok_or_else(short)?);
    let block = match blocks {
        true => u32::from_be_bytes(take::<4>(data, &mut at).ok_or_else(short)?),
        false => 0,
    };
    if at != data.len() {
        return Err(format!("{} bytes follow its fields", data.len() - at));
    }
    if blocks && !(MIN_BLOCK..=MAX_BLOCK).contains(&block) {
        return Err(format!("a block of {block} bytes, where {MIN_BLOCK} to {MAX_BLOCK} are allowed"));
    }
    Ok(Asked { handle, offset, len, block })
}

/// The data of a reply: uint64 size, uint64 mtime, uint64 hashed, uint32
/// block, uint32 count, then each digest.
pub fn encode_reply(sums: &Sums) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD + 32 * sums.sums.len());
    out.extend_from_slice(&sums.size.to_be_bytes());
    out.extend_from_slice(&sums.mtime.to_be_bytes());
    out.extend_from_slice(&sums.hashed.to_be_bytes());
    out.extend_from_slice(&sums.block.to_be_bytes());
    out.extend_from_slice(&(sums.sums.len() as u32).to_be_bytes());
    for sum in &sums.sums {
        out.extend_from_slice(sum);
    }
    out
}

/// A reply to `asked`, checked against it: its length, a range no longer
/// than asked, the block asked, and one digest for each block.
pub fn parse_reply(data: &[u8], asked: &Asked) -> Result<Sums, String> {
    let short = || format!("a reply of {} bytes, shorter than its head", data.len());
    let mut at = 0;
    let size = u64::from_be_bytes(take::<8>(data, &mut at).ok_or_else(short)?);
    let mtime = u64::from_be_bytes(take::<8>(data, &mut at).ok_or_else(short)?);
    let hashed = u64::from_be_bytes(take::<8>(data, &mut at).ok_or_else(short)?);
    let block = u32::from_be_bytes(take::<4>(data, &mut at).ok_or_else(short)?);
    let count = u64::from(u32::from_be_bytes(take::<4>(data, &mut at).ok_or_else(short)?));
    if asked.len != 0 && hashed > asked.len {
        return Err(format!("{hashed} bytes hashed, where {} were asked", asked.len));
    }
    if block != asked.block {
        return Err(format!("blocks of {block} bytes, where {} were asked", asked.block));
    }
    if count != blocks_of(hashed, block) || count > MAX_BLOCKS {
        return Err(format!("{count} digests for {hashed} bytes in blocks of {block}"));
    }
    let want = HEAD as u64 + 32 * count;
    if data.len() as u64 != want {
        return Err(format!("a reply of {} bytes, where its count makes {want}", data.len()));
    }
    let sums = data[HEAD..].chunks_exact(32).map(|c| c.try_into().unwrap_or([0; 32])).collect();
    Ok(Sums { size, mtime, hashed, block, sums })
}

/// Hash `len` bytes from `offset`, or fewer at the end of the file, with
/// `read_at` (a positioned read that gives 0 at the end): one digest of the
/// range when `block` is 0, else one for each block, the last one short.
/// The bytes hashed, and the digests.
pub fn hash_range(
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    offset: u64,
    len: u64,
    block: u32,
) -> io::Result<(u64, Vec<Sum>)> {
    let mut buf = vec![0u8; 1 << 20];
    let (mut done, mut sums) = (0u64, Vec::new());
    let mut hasher = Sha256::new();
    let mut in_block = 0u64;
    while done < len {
        let want = (len - done).min(buf.len() as u64) as usize;
        let n = match read_at(&mut buf[..want], offset.saturating_add(done)) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if n == 0 {
            break;
        }
        let mut part = &buf[..n.min(want)];
        while !part.is_empty() {
            // A block ends inside this read: hash to its end, close it.
            let room = match block {
                0 => part.len(),
                b => (u64::from(b) - in_block).min(part.len() as u64) as usize,
            };
            hasher.update(&part[..room]);
            in_block += room as u64;
            part = &part[room..];
            if block != 0 && in_block == u64::from(block) {
                sums.push(std::mem::take(&mut hasher).finalize().into());
                in_block = 0;
            }
        }
        done += n.min(want) as u64;
    }
    if block == 0 || in_block > 0 {
        sums.push(hasher.finalize().into());
    }
    Ok((done, sums))
}

impl Sftp {
    /// The SHA-256 of `len` bytes of `file` from `offset` (fewer at its
    /// end), or of each block of `block` bytes of that range when `block`
    /// is not 0, by podssh's own request. `None` when the server does not
    /// list the request: the caller then reads or runs a tool (T-134).
    pub async fn sums(&self, file: &FileHandle, offset: u64, len: u64, block: u32) -> Result<Option<Sums>, SftpError> {
        let name = if block == 0 { SHA256 } else { SHA256_BLOCKS };
        if !self.has(name) {
            return Ok(None);
        }
        let asked = Asked { handle: file.0.clone(), offset, len, block };
        let what = format!("{name} of {len} bytes at {offset}");
        let limit = reply_limit(self.limits.metadata, len);
        match within(limit, &what, self.raw.extended(name, encode_request(&asked))).await? {
            Packet::ExtendedReply(r) => {
                parse_reply(&r.data, &asked).map(Some).map_err(|why| SftpError::Protocol(format!("{what}: {why}")))
            }
            Packet::Status(s) => Err(SftpError::from_raw(&what, russh_sftp::client::error::Error::Status(s), limit)),
            _ => Err(SftpError::Protocol(format!("{what}: a reply of the wrong type"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect()
    }

    fn sha(bytes: &[u8]) -> Sum {
        Sha256::digest(bytes).into()
    }

    /// A positioned read of `bytes` that gives at most `most` each call, as
    /// a short read of a pipe or a network file does.
    fn reader(bytes: &[u8], most: usize) -> impl FnMut(&mut [u8], u64) -> io::Result<usize> + '_ {
        move |buf, at| {
            let at = (at as usize).min(bytes.len());
            let n = buf.len().min(most).min(bytes.len() - at);
            buf[..n].copy_from_slice(&bytes[at..at + n]);
            Ok(n)
        }
    }

    /// One rule for each case: the digests are those of the bytes in the
    /// range, cut where the file ends, in blocks of `block`.
    #[test]
    fn each_range_hashes_its_bytes_in_its_blocks() {
        let file = data(3 * 1024 * 1024 + 17);
        let n = file.len() as u64;
        for (offset, len, block, most) in [
            (0, n, 0, usize::MAX),
            (0, n + 1, 0, 4096),
            (5, 100, 0, 7),
            (n, 10, 0, usize::MAX),
            (n + 9, 10, 0, usize::MAX),
            (0, 0, 0, usize::MAX),
            (0, n, 1024, 1000),
            (3, n, MAX_BLOCK, usize::MAX),
            (0, 4096, 1024, usize::MAX),
            (1, 1 << 20, 4096, 333),
        ] {
            let (hashed, sums) = hash_range(reader(&file, most), offset, len, block).unwrap();
            let start = (offset as usize).min(file.len());
            let end = (offset.saturating_add(len) as usize).min(file.len());
            let range = &file[start..end];
            assert_eq!(hashed, range.len() as u64, "{offset} {len} {block}");
            let want: Vec<Sum> = match block {
                0 => vec![sha(range)],
                b => range.chunks(b as usize).map(sha).collect(),
            };
            assert_eq!(sums, want, "{offset} {len} {block}");
            assert_eq!(sums.len() as u64, blocks_of(hashed, block));
        }
    }

    #[test]
    fn a_read_that_fails_fails_the_hash() {
        let failing = |_: &mut [u8], _: u64| Err(io::Error::other("planted"));
        assert!(hash_range(failing, 0, 10, 0).is_err());
    }

    #[test]
    fn a_request_and_a_reply_go_and_come_back_whole() {
        for asked in [
            Asked { handle: "1".into(), offset: 0, len: 0, block: 0 },
            Asked { handle: "handle-é".into(), offset: u64::MAX, len: 7, block: 0 },
            Asked { handle: "9".into(), offset: 3, len: 1 << 40, block: MIN_BLOCK },
        ] {
            let blocks = asked.block != 0;
            assert_eq!(parse_request(&encode_request(&asked), blocks).unwrap(), asked);
        }
        let asked = Asked { handle: "1".into(), offset: 0, len: 3000, block: 1024 };
        let sums = Sums { size: 5000, mtime: 7, hashed: 3000, block: 1024, sums: vec![[1; 32], [2; 32], [3; 32]] };
        assert_eq!(parse_reply(&encode_reply(&sums), &asked).unwrap(), sums);
    }

    /// Each broken request is refused with its reason, never read past.
    #[test]
    fn a_broken_request_is_refused() {
        let good = encode_request(&Asked { handle: "1".into(), offset: 0, len: 9, block: 4096 });
        let mut long = good.clone();
        long.push(0);
        let mut huge = vec![0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&good[4..]);
        let mut not_utf8 = good.clone();
        not_utf8[4] = 0xff;
        let tiny = encode_request(&Asked { handle: "1".into(), offset: 0, len: 9, block: 512 });
        for (data, blocks, says) in [
            (&good[..good.len() - 1], true, "shorter"),
            (&long[..], true, "follow"),
            (&huge[..], true, "shorter"),
            (&not_utf8[..], true, "UTF-8"),
            (&tiny[..], true, "allowed"),
            (&good[..], false, "follow"),
            (&[][..], false, "shorter"),
        ] {
            let why = parse_request(data, blocks).unwrap_err();
            assert!(why.contains(says), "{why}");
        }
    }

    /// Each reply that does not fit its request breaks the protocol.
    #[test]
    fn a_reply_that_does_not_fit_its_request_is_refused() {
        let asked = Asked { handle: "1".into(), offset: 0, len: 2048, block: 1024 };
        let good = Sums { size: 2048, mtime: 1, hashed: 2048, block: 1024, sums: vec![[0; 32]; 2] };
        let longer = Sums { hashed: 4096, sums: vec![[0; 32]; 4], ..good.clone() };
        let other_block = Sums { block: 2048, sums: vec![[0; 32]], ..good.clone() };
        let missing = Sums { sums: vec![[0; 32]], ..good.clone() };
        for (sums, says) in [(longer, "asked"), (other_block, "asked"), (missing, "digests")] {
            let why = parse_reply(&encode_reply(&sums), &asked).unwrap_err();
            assert!(why.contains(says), "{why}");
        }
        let bytes = encode_reply(&good);
        assert!(parse_reply(&bytes[..bytes.len() - 1], &asked).unwrap_err().contains("count makes"));
        assert!(parse_reply(&bytes[..10], &asked).unwrap_err().contains("shorter"));
    }

    #[test]
    fn the_limit_grows_with_the_range() {
        let base = Duration::from_secs(30);
        assert_eq!(reply_limit(base, 0), base);
        assert_eq!(reply_limit(base, DISK_RATE * 10), base + Duration::from_secs(10));
        assert_eq!(reply_limit(Duration::MAX, u64::MAX), Duration::MAX);
    }
}
