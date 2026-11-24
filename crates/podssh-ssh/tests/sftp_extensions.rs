//! podssh's own SFTP requests (T-150), `sha256@podssh` and
//! `sha256-blocks@podssh`: podssh's client against the SFTP server of
//! `podssh serve` over a pipe, each digest against the disk; a digest sent
//! in the same pipeline as a write covers the write; the bounds of a
//! request, each refused with its reason while the session goes on; a
//! server that does not list the requests gives `None`, the fallback of
//! T-134 (OpenSSH's `sftp-server`, where this host has one); and a server
//! whose reply does not fit its request breaks the protocol.

#![cfg(unix)]

mod cleanup;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use podssh_ssh::server::sftp::{serve, CALL_LIMIT};
use podssh_ssh::sftp::sums::{self, Sum, MAX_BLOCKS, SHA256, SHA256_BLOCKS};
use podssh_ssh::sftp::{FileAttributes, Limits, OpenFlags, Sftp, SftpError};
use russh_sftp::protocol::{Extended, ExtendedReply, Handle, Init, Open, Packet, StatusCode, Version, Write};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A bound on each wait of a test.
const WAIT: Duration = Duration::from_secs(30);

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-sftp-ext-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir.canonicalize().unwrap()
}

fn data(n: usize) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect()
}

fn sha(bytes: &[u8]) -> Sum {
    Sha256::digest(bytes).into()
}

async fn bounded<T>(call: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, call).await.expect("within the test's own limit")
}

/// podssh's client on a new server of `podssh serve` in `home`.
async fn client(home: &Path) -> Sftp {
    let (near, far) = tokio::io::duplex(1 << 22);
    let (input, output) = tokio::io::split(far);
    tokio::spawn(serve(input, output, home.to_path_buf(), CALL_LIMIT));
    bounded(Sftp::over(near, Limits::default())).await.expect("the version exchange")
}

/// One rule for each row: the digests are those of the bytes of the range
/// on the disk, cut where the file ends, and the reply names the file's size.
#[tokio::test]
async fn each_digest_from_podssh_serve_is_the_one_of_the_disk() {
    let home = scratch("digests");
    let file = data(3 * 1024 * 1024 + 17);
    std::fs::write(home.join("f.bin"), &file).unwrap();
    let sftp = client(&home).await;
    assert!(sftp.has(SHA256) && sftp.has(SHA256_BLOCKS));
    let handle = bounded(sftp.open_file("f.bin", OpenFlags::READ, FileAttributes::empty())).await.unwrap();
    let n = file.len() as u64;
    for (offset, len, block) in [
        (0, n, 0),
        (0, n + 1, 0),
        (0, 0, 0),
        (5, 100, 0),
        (n, 10, 0),
        (n + 9, 10, 0),
        (0, n, 4096),
        (0, 0, 1 << 20),
        (7, 1_000_000, 1024),
        (0, n + 1, 64 << 20),
    ] {
        let got = bounded(sftp.sums(&handle, offset, len, block)).await.unwrap().expect("the server lists it");
        let start = (offset as usize).min(file.len());
        // Length 0 is the rest of the file.
        let end = if len == 0 { file.len() } else { (offset.saturating_add(len) as usize).min(file.len()) };
        let range = &file[start..end];
        let want: Vec<Sum> = match block {
            0 => vec![sha(range)],
            b => range.chunks(b as usize).map(sha).collect(),
        };
        assert_eq!((got.hashed, got.block, got.size), (range.len() as u64, block, n), "{offset} {len} {block}");
        assert!(got.sums == want, "the digests of {offset} {len} {block} differ from the disk's");
    }
    bounded(sftp.close(&handle)).await.unwrap();
}

/// The client's end of a server, spoken in packets.
struct Raw {
    stream: DuplexStream,
}

impl Raw {
    async fn send(&mut self, packet: Packet) {
        let bytes = Bytes::try_from(packet).unwrap();
        self.stream.write_all(&bytes).await.unwrap();
    }

    async fn recv(&mut self) -> Packet {
        bounded(async {
            let len = self.stream.read_u32().await.unwrap();
            let mut body = vec![0u8; len as usize];
            self.stream.read_exact(&mut body).await.unwrap();
            Packet::try_from(&mut Bytes::from(body)).unwrap()
        })
        .await
    }
}

/// The donor study's rule (libfuse/sshfs orders a request behind the
/// handle's writes): a digest sent before the write's reply came still
/// covers the write.
#[tokio::test]
async fn a_digest_in_the_same_pipeline_as_a_write_covers_the_write() {
    let home = scratch("pipeline");
    let (stream, far) = tokio::io::duplex(1 << 22);
    let (input, output) = tokio::io::split(far);
    tokio::spawn(serve(input, output, home.clone(), CALL_LIMIT));
    let mut raw = Raw { stream };
    raw.send(Packet::Init(Init { version: 3, extensions: HashMap::new() })).await;
    assert!(matches!(raw.recv().await, Packet::Version(_)));
    let pflags = OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
    let attrs = FileAttributes::empty();
    raw.send(Packet::Open(Open { id: 1, filename: "w.bin".into(), pflags, attrs })).await;
    let Packet::Handle(Handle { handle, .. }) = raw.recv().await else { panic!("no handle") };
    let written = data(200_000);
    let asked = sums::Asked { handle: handle.clone(), offset: 0, len: 1 << 30, block: 0 };
    // Both requests go before either reply is read.
    raw.send(Packet::Write(Write { id: 2, handle, offset: 0, data: written.clone() })).await;
    raw.send(Packet::Extended(Extended { id: 3, request: SHA256.into(), data: sums::encode_request(&asked) })).await;
    match raw.recv().await {
        Packet::Status(s) => assert_eq!((s.id, s.status_code), (2, StatusCode::Ok)),
        other => panic!("the write's reply comes first: {other:?}"),
    }
    let Packet::ExtendedReply(r) = raw.recv().await else { panic!("no digest") };
    assert_eq!(r.id, 3);
    let got = sums::parse_reply(&r.data, &asked).unwrap();
    assert_eq!((got.hashed, got.size), (written.len() as u64, written.len() as u64));
    assert_eq!(got.sums, vec![sha(&written)], "the digest misses the write before it");
}

/// Each request past a bound is refused with its reason, and the session
/// goes on: the next request is answered.
#[tokio::test]
async fn a_request_past_its_bounds_is_refused_and_the_session_goes_on() {
    let home = scratch("bounds");
    let blocks = (MAX_BLOCKS as usize + 1) * 1024;
    std::fs::write(home.join("big.bin"), data(blocks)).unwrap();
    let sftp = client(&home).await;
    let handle = bounded(sftp.open_file("big.bin", OpenFlags::READ, FileAttributes::empty())).await.unwrap();
    let too_many = bounded(sftp.sums(&handle, 0, 0, 1024)).await.unwrap_err();
    assert!(
        matches!(&too_many, SftpError::Status { code, message, .. }
            if *code == StatusCode::Failure as u32 && message.contains("shorter range")),
        "{too_many:?}"
    );
    let small_block = bounded(sftp.sums(&handle, 0, 0, 512)).await.unwrap_err();
    assert!(
        matches!(&small_block, SftpError::Status { code, .. } if *code == StatusCode::BadMessage as u32),
        "{small_block:?}"
    );
    // The same range in blocks of 2 KiB fits.
    let fits = bounded(sftp.sums(&handle, 0, 0, 2048)).await.unwrap().unwrap();
    assert_eq!(fits.sums.len() as u64, sums::blocks_of(blocks as u64, 2048));
    bounded(sftp.close(&handle)).await.unwrap();
    // A handle that is closed is no handle.
    let closed = bounded(sftp.sums(&handle, 0, 10, 0)).await.unwrap_err();
    assert!(matches!(&closed, SftpError::Status { message, .. } if message.contains("no open file")), "{closed:?}");
}

/// OpenSSH's sftp-server where this host has one, as `tests/sftp_client.rs`
/// finds it.
fn sftp_server() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os("PODSSH_TEST_SFTP_SERVER") {
        return Some(named.into());
    }
    ["/usr/lib/ssh/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// A standard server does not list the requests: no request goes, and the
/// caller takes T-134's way.
#[tokio::test]
async fn a_server_that_does_not_list_the_requests_gives_none() {
    let Some(server) = sftp_server() else {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    };
    let dir = scratch("openssh");
    std::fs::write(dir.join("f"), b"bytes").unwrap();
    let mut child = tokio::process::Command::new(server)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the sftp-server starts");
    let pipes = tokio::io::join(child.stdout.take().unwrap(), child.stdin.take().unwrap());
    let sftp = bounded(Sftp::over(pipes, Limits::default())).await.unwrap();
    assert!(!sftp.has(SHA256) && !sftp.has(SHA256_BLOCKS));
    let handle = bounded(sftp.open_file("f", OpenFlags::READ, FileAttributes::empty())).await.unwrap();
    assert_eq!(bounded(sftp.sums(&handle, 0, 5, 0)).await.unwrap(), None);
    assert_eq!(bounded(sftp.sums(&handle, 0, 5, 1024)).await.unwrap(), None);
}

/// A server that lists the request and answers with a reply that does not
/// fit it: each such reply is a protocol error, never a digest.
#[tokio::test]
async fn a_reply_that_does_not_fit_its_request_breaks_the_protocol() {
    let (near, far) = tokio::io::duplex(1 << 16);
    let fake = tokio::spawn(async move {
        let mut raw = Raw { stream: far };
        assert!(matches!(raw.recv().await, Packet::Init(_)));
        let extensions = HashMap::from([(SHA256.to_string(), "1".to_string())]);
        raw.send(Packet::Version(Version { version: 3, extensions })).await;
        let Packet::Open(open) = raw.recv().await else { panic!("no open") };
        raw.send(Packet::Handle(Handle { id: open.id, handle: "1".into() })).await;
        // Two digests where one range asked for one, then a short reply.
        let two = sums::Sums { size: 5, mtime: 0, hashed: 5, block: 0, sums: vec![[0; 32]; 2] };
        for data in [sums::encode_reply(&two), vec![0u8; 10]] {
            let Packet::Extended(e) = raw.recv().await else { panic!("no request") };
            raw.send(Packet::ExtendedReply(ExtendedReply { id: e.id, data })).await;
        }
    });
    let sftp = bounded(Sftp::over(near, Limits::default())).await.unwrap();
    let handle = bounded(sftp.open_file("f", OpenFlags::READ, FileAttributes::empty())).await.unwrap();
    for _ in 0..2 {
        let broke = bounded(sftp.sums(&handle, 0, 5, 0)).await.unwrap_err();
        assert!(matches!(broke, SftpError::Protocol(_)), "{broke:?}");
    }
    bounded(fake).await.unwrap();
}
