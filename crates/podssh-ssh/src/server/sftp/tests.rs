//! The SFTP server's packets, written and read as bytes over a pipe: the
//! version exchange, each refusal with its code, its id and its words, the
//! bounds of a session, and a session of podssh's own client against it.

use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh_sftp::protocol::{
    Close, Extended, FileAttributes, Init, Lstat, Open as OpenFile, OpenFlags, Packet, Read, ReadLink, RealPath,
    Rename, StatusCode, Symlink,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use super::*;

/// The id of a reply: russh-sftp's `get_request_id` reads requests alone,
/// and gives 0 for each reply.
fn reply_id(reply: &Packet) -> u32 {
    match reply {
        Packet::Status(p) => p.id,
        Packet::Handle(p) => p.id,
        Packet::Data(p) => p.id,
        Packet::Name(p) => p.id,
        Packet::Attrs(p) => p.id,
        Packet::ExtendedReply(p) => p.id,
        other => panic!("not a reply: {other:?}"),
    }
}

/// A bound on each wait of a test.
const WAIT: Duration = Duration::from_secs(10);

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-sftp-server-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

/// The client's end of a server over a pipe, and the server's task.
struct Peer {
    stream: DuplexStream,
    next: u32,
    server: JoinHandle<Result<(), String>>,
}

impl Peer {
    async fn start(home: &Path, limit: Duration) -> Peer {
        let (stream, far) = tokio::io::duplex(1 << 22);
        let (input, output) = tokio::io::split(far);
        let server = tokio::spawn(serve(input, output, home.to_path_buf(), limit));
        let mut peer = Peer { stream, next: 0, server };
        peer.send(Packet::Init(Init { version: 3, extensions: HashMap::new() })).await;
        match peer.recv().await {
            Packet::Version(v) => assert_eq!(v.version, 3),
            other => panic!("not a version: {other:?}"),
        }
        peer
    }

    async fn send(&mut self, packet: Packet) {
        let bytes = Bytes::try_from(packet).unwrap();
        self.stream.write_all(&bytes).await.unwrap();
    }

    async fn send_body(&mut self, body: &[u8]) {
        self.stream.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
        self.stream.write_all(body).await.unwrap();
    }

    async fn recv(&mut self) -> Packet {
        tokio::time::timeout(WAIT, async {
            let len = self.stream.read_u32().await.unwrap();
            let mut body = vec![0u8; len as usize];
            self.stream.read_exact(&mut body).await.unwrap();
            Packet::try_from(&mut Bytes::from(body)).unwrap()
        })
        .await
        .expect("a reply in time")
    }

    /// One request, made with its id, and its reply.
    async fn ask(&mut self, make: impl FnOnce(u32) -> Packet) -> Packet {
        self.next += 1;
        let id = self.next;
        self.send(make(id)).await;
        let reply = self.recv().await;
        assert_eq!(reply_id(&reply), id, "{reply:?}");
        reply
    }

    async fn open(&mut self, name: &str, pflags: OpenFlags) -> Packet {
        let filename = name.to_string();
        self.ask(|id| Packet::Open(OpenFile { id, filename, pflags, attrs: FileAttributes::empty() })).await
    }
}

/// The handle of a reply, or the reply.
fn handle(reply: Packet) -> String {
    match reply {
        Packet::Handle(h) => h.handle,
        other => panic!("not a handle: {other:?}"),
    }
}

/// The code and the words of a status reply.
fn said(reply: &Packet) -> (StatusCode, String) {
    match reply {
        Packet::Status(s) => (s.status_code, s.error_message.clone()),
        other => panic!("not a status: {other:?}"),
    }
}

#[tokio::test]
async fn the_version_reply_names_three_extensions_and_version_3() {
    let home = scratch("version");
    let (mut stream, far) = tokio::io::duplex(1 << 16);
    let (input, output) = tokio::io::split(far);
    tokio::spawn(serve(input, output, home, CALL_LIMIT));
    // A client that asks for version 6 gets 3, as sftp-server answers.
    let init = Bytes::try_from(Packet::Init(Init { version: 6, extensions: HashMap::new() })).unwrap();
    stream.write_all(&init).await.unwrap();
    let len = stream.read_u32().await.unwrap();
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await.unwrap();
    match Packet::try_from(&mut Bytes::from(body)).unwrap() {
        Packet::Version(v) => {
            assert_eq!(v.version, 3);
            for name in [POSIX_RENAME, FSYNC, LIMITS] {
                assert_eq!(v.extensions.get(name).map(String::as_str), Some("1"), "{name}");
            }
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_request_before_init_and_a_second_init_end_the_session() {
    let home = scratch("init");
    let (mut stream, far) = tokio::io::duplex(1 << 16);
    let (input, output) = tokio::io::split(far);
    let server = tokio::spawn(serve(input, output, home.clone(), CALL_LIMIT));
    let stat = Bytes::try_from(Packet::Lstat(Lstat { id: 1, path: ".".into() })).unwrap();
    stream.write_all(&stat).await.unwrap();
    let ended = tokio::time::timeout(WAIT, server).await.expect("in time").unwrap();
    assert!(ended.unwrap_err().contains("SSH_FXP_INIT comes first"));

    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    peer.send(Packet::Init(Init { version: 3, extensions: HashMap::new() })).await;
    let ended = tokio::time::timeout(WAIT, peer.server).await.expect("in time").unwrap();
    assert!(ended.unwrap_err().contains("second"));
}

#[tokio::test]
async fn an_unknown_type_and_a_broken_packet_are_answered_with_their_id_and_the_session_goes_on() {
    let home = scratch("unknown");
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    // Type 99 with the id 7.
    peer.send_body(&[99, 0, 0, 0, 7, 1, 2, 3]).await;
    let reply = peer.recv().await;
    assert_eq!(reply_id(&reply), 7);
    assert_eq!(said(&reply).0, StatusCode::OpUnsupported, "{reply:?}");
    // OPEN with the id 5 and a name cut short.
    peer.send_body(&[3, 0, 0, 0, 5, 0, 0, 0, 9, b'a']).await;
    let reply = peer.recv().await;
    assert_eq!(reply_id(&reply), 5);
    assert_eq!(said(&reply).0, StatusCode::BadMessage, "{reply:?}");
    let reply = peer.ask(|id| Packet::RealPath(RealPath { id, path: ".".into() })).await;
    assert!(matches!(reply, Packet::Name(_)), "{reply:?}");
}

#[tokio::test]
async fn a_packet_past_the_limit_ends_the_session() {
    let home = scratch("long");
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    peer.stream.write_all(&(MAX_PACKET + 1).to_be_bytes()).await.unwrap();
    let ended = tokio::time::timeout(WAIT, peer.server).await.expect("in time").unwrap();
    assert!(ended.unwrap_err().contains("the most"));
}

#[tokio::test]
async fn a_missing_file_is_no_such_file_with_its_name_and_a_relative_path_starts_at_home() {
    let home = scratch("paths");
    std::fs::write(home.join("here.txt"), b"hello").unwrap();
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let reply = peer.open("absent.txt", OpenFlags::READ).await;
    let (code, words) = said(&reply);
    assert_eq!(code, StatusCode::NoSuchFile);
    assert!(words.contains("absent.txt") && words.contains("No such file"), "{words}");
    assert!(!words.contains("os error"), "{words}");
    let h = handle(peer.open("here.txt", OpenFlags::READ).await);
    let reply = peer.ask(|id| Packet::Read(Read { id, handle: h.clone(), offset: 0, len: 100 })).await;
    match reply {
        Packet::Data(d) => assert_eq!(d.data, b"hello"),
        other => panic!("{other:?}"),
    }
    for path in ["", "."] {
        let reply = peer.ask(|id| Packet::RealPath(RealPath { id, path: path.into() })).await;
        match reply {
            Packet::Name(n) => assert_eq!(Path::new(&n.files[0].filename), home.as_path(), "{path:?}"),
            other => panic!("{other:?}"),
        }
    }
    // The name of a file about to be made: its directory exists.
    let reply = peer.ask(|id| Packet::RealPath(RealPath { id, path: "new.txt".into() })).await;
    match reply {
        Packet::Name(n) => assert_eq!(Path::new(&n.files[0].filename), home.join("new.txt")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_read_is_cut_to_the_limit_and_the_end_of_the_file_is_eof() {
    let home = scratch("read");
    std::fs::write(home.join("big"), vec![7u8; 300 * 1024]).unwrap();
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let h = handle(peer.open("big", OpenFlags::READ).await);
    let reply = peer.ask(|id| Packet::Read(Read { id, handle: h.clone(), offset: 0, len: 1 << 20 })).await;
    match reply {
        Packet::Data(d) => assert_eq!(d.data.len(), MAX_READ as usize),
        other => panic!("{other:?}"),
    }
    let reply = peer.ask(|id| Packet::Read(Read { id, handle: h.clone(), offset: 300 * 1024, len: 10 })).await;
    assert_eq!(said(&reply).0, StatusCode::Eof);
    let reply = peer.ask(|id| Packet::Close(Close { id, handle: h.clone() })).await;
    assert_eq!(said(&reply).0, StatusCode::Ok);
    // A closed handle is no handle.
    let reply = peer.ask(|id| Packet::Read(Read { id, handle: h.clone(), offset: 0, len: 10 })).await;
    assert_eq!(said(&reply).0, StatusCode::Failure);
}

#[tokio::test]
async fn the_handles_are_bounded_and_a_close_makes_room() {
    let home = scratch("handles");
    std::fs::write(home.join("f"), b"x").unwrap();
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let mut open = Vec::new();
    for _ in 0..MAX_HANDLES {
        open.push(handle(peer.open("f", OpenFlags::READ).await));
    }
    let reply = peer.open("f", OpenFlags::READ).await;
    let (code, words) = said(&reply);
    assert_eq!(code, StatusCode::Failure);
    assert!(words.contains(&MAX_HANDLES.to_string()), "{words}");
    let first = open.remove(0);
    peer.ask(|id| Packet::Close(Close { id, handle: first })).await;
    handle(peer.open("f", OpenFlags::READ).await);
}

#[tokio::test]
async fn a_fifo_with_no_writer_fails_within_the_limit_and_the_session_goes_on() {
    let home = scratch("fifo");
    let fifo = std::ffi::CString::new(home.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid C string.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let limit = Duration::from_millis(500);
    let mut peer = Peer::start(&home, limit).await;
    let started = Instant::now();
    let reply = peer.open("fifo", OpenFlags::READ).await;
    let (code, words) = said(&reply);
    assert_eq!(code, StatusCode::Failure);
    assert!(words.contains("no answer within"), "{words}");
    assert!(started.elapsed() < limit + Duration::from_secs(3), "{:?}", started.elapsed());
    let reply = peer.ask(|id| Packet::Lstat(Lstat { id, path: "fifo".into() })).await;
    match reply {
        Packet::Attrs(a) => assert_eq!(a.attrs.permissions.unwrap() & 0o170_000, 0o010_000),
        other => panic!("{other:?}"),
    }
    // A writer frees the thread that waits in open(2).
    let _ = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(home.join("fifo"));
}

#[tokio::test]
async fn symlink_takes_the_target_first_as_openssh_does() {
    let home = scratch("symlink");
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let reply =
        peer.ask(|id| Packet::Symlink(Symlink { id, linkpath: "target.txt".into(), targetpath: "link".into() })).await;
    assert_eq!(said(&reply).0, StatusCode::Ok, "{reply:?}");
    assert_eq!(std::fs::read_link(home.join("link")).unwrap(), PathBuf::from("target.txt"));
    let reply = peer.ask(|id| Packet::ReadLink(ReadLink { id, path: "link".into() })).await;
    match reply {
        Packet::Name(n) => assert_eq!(n.files[0].filename, "target.txt"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn rename_keeps_an_existing_name_and_posix_rename_replaces_it() {
    let home = scratch("rename");
    std::fs::write(home.join("a"), b"A").unwrap();
    std::fs::write(home.join("b"), b"B").unwrap();
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let reply = peer.ask(|id| Packet::Rename(Rename { id, oldpath: "a".into(), newpath: "b".into() })).await;
    assert_eq!(said(&reply).0, StatusCode::Failure, "{reply:?}");
    assert_eq!(std::fs::read(home.join("b")).unwrap(), b"B");
    let mut data = Vec::new();
    for part in ["a", "b"] {
        data.extend_from_slice(&(part.len() as u32).to_be_bytes());
        data.extend_from_slice(part.as_bytes());
    }
    let reply = peer.ask(|id| Packet::Extended(Extended { id, request: POSIX_RENAME.into(), data })).await;
    assert_eq!(said(&reply).0, StatusCode::Ok, "{reply:?}");
    assert_eq!(std::fs::read(home.join("b")).unwrap(), b"A");
    assert!(!home.join("a").exists());
    let reply = peer.ask(|id| Packet::Extended(Extended { id, request: "nope@example".into(), data: vec![] })).await;
    assert_eq!(said(&reply).0, StatusCode::OpUnsupported);
}

#[tokio::test]
async fn limits_names_the_bounds_of_the_session() {
    let home = scratch("limits");
    let mut peer = Peer::start(&home, CALL_LIMIT).await;
    let reply = peer.ask(|id| Packet::Extended(Extended { id, request: LIMITS.into(), data: vec![] })).await;
    let Packet::ExtendedReply(r) = reply else { panic!("{reply:?}") };
    let n = |i: usize| u64::from_be_bytes(r.data[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(r.data.len(), 32);
    assert_eq!((n(0), n(1), n(2), n(3)), (MAX_PACKET as u64, MAX_READ as u64, MAX_READ as u64, MAX_HANDLES as u64));
}

#[tokio::test]
async fn podssh_s_own_client_moves_a_file_lists_and_changes_it() {
    use crate::sftp::{Limits, Sftp};
    let home = scratch("client");
    let (near, far) = tokio::io::duplex(1 << 22);
    let (input, output) = tokio::io::split(far);
    tokio::spawn(serve(input, output, home.clone(), CALL_LIMIT));
    let sftp = Sftp::over(near, Limits::default()).await.unwrap();
    assert!(sftp.has(POSIX_RENAME) && sftp.has(FSYNC));
    assert_eq!(sftp.write_len(), MAX_READ);
    let sent: Vec<u8> = (0..1_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
    let file = sftp.open_file("up.bin", flags, FileAttributes::empty()).await.unwrap();
    sftp.write(&file, 0, &sent).await.unwrap();
    assert!(sftp.fsync(&file).await.unwrap());
    sftp.close(&file).await.unwrap();
    assert!(std::fs::read(home.join("up.bin")).unwrap() == sent, "the bytes arrived changed");
    let file = sftp.open_file("up.bin", OpenFlags::READ, FileAttributes::empty()).await.unwrap();
    let mut back = Vec::new();
    while let Some(part) = sftp.read(&file, back.len() as u64, sftp.read_len()).await.unwrap() {
        back.extend_from_slice(&part);
    }
    assert!(back == sent, "the bytes came back changed");
    sftp.mkdir("dir", FileAttributes::empty()).await.unwrap();
    sftp.rename("up.bin", "dir/moved.bin").await.unwrap();
    let names: Vec<String> = sftp.read_dir("dir").await.unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec![".", "..", "moved.bin"]);
    let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::empty() };
    sftp.setstat("dir/moved.bin", attrs).await.unwrap();
    let got = sftp.stat("dir/moved.bin").await.unwrap();
    assert_eq!((got.size, got.permissions.map(|p| p & 0o7777)), (Some(sent.len() as u64), Some(0o600)));
    sftp.remove("dir/moved.bin").await.unwrap();
    sftp.rmdir("dir").await.unwrap();
    assert!(sftp.stat("dir").await.unwrap_err().is_missing());
}
