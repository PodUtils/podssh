//! The SFTP server of `podssh serve` (T-112) with podssh's own SFTP client
//! over russh's client and a pipe: 5,000,000 bytes up and back with equal
//! SHA-256 digests; a relative path starts at `HOME`; mkdir, rename over a
//! name (posix-rename), a listing, a link, remove and rmdir; each refusal with
//! its code and words; the bound of open handles; a FIFO with no writer fails
//! within the time limit, and the session goes on. The same against OpenSSH's
//! `sftp`: `podssh-cli`'s `tests/serve_sftp_openssh.rs`.

#![cfg(unix)]

mod cleanup;

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client, ChannelMsg};
use podssh_ssh::server::sftp::MAX_HANDLES;
use podssh_ssh::server::{self, Authorized, Settings};
use podssh_ssh::sftp::{FileAttributes, Limits, OpenFlags, Sftp, SftpError};
use sha2::{Digest, Sha256};

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-sftp-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir.canonicalize().unwrap()
}

/// serve's settings with `home` as its HOME.
fn settings(home: &Path) -> Settings {
    let base: Vec<(OsString, OsString)> = vec![("HOME".into(), home.as_os_str().to_os_string())];
    Settings { base_env: Some(base), ..Settings::default() }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A logged-in connection to a new server with `settings`.
async fn connect(settings: Settings) -> client::Handle<Trusting> {
    // Room for a batch of each end: two russh loops on a pipe of 64 KiB
    // stop each other (T-772).
    let (near, far) = tokio::io::duplex(1 << 22);
    let login = key();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    tokio::spawn(server::serve_with(far, key(), Arc::new(authorized), Arc::new(settings)));
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), near, Trusting).await.unwrap();
    let login = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    assert!(handle.authenticate_publickey("anyone", login).await.unwrap().success());
    handle
}

/// An SFTP session on a new channel of `handle`, once the server said yes.
async fn sftp(handle: &client::Handle<Trusting>) -> Sftp {
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let granted = tokio::time::timeout(LIMIT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return true,
                Some(ChannelMsg::Failure) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("an answer to the subsystem request");
    assert!(granted, "the sftp subsystem must be served");
    tokio::time::timeout(LIMIT, Sftp::over(channel.into_stream(), Limits::default()))
        .await
        .expect("the version exchange in time")
        .unwrap()
}

fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_goes_up_and_comes_back_whole() {
    let home = scratch("whole");
    let handle = connect(settings(&home)).await;
    let sftp = sftp(&handle).await;
    let sent: Vec<u8> = (0..5_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
    let file = sftp.open_file("up.bin", flags, FileAttributes::empty()).await.unwrap();
    sftp.write(&file, 0, &sent).await.unwrap();
    assert!(sftp.fsync(&file).await.unwrap(), "fsync@openssh.com is served");
    sftp.close(&file).await.unwrap();
    // A relative path is under HOME.
    let landed = std::fs::read(home.join("up.bin")).unwrap();
    assert_eq!(landed.len(), sent.len());
    assert_eq!(digest(&landed), digest(&sent), "the file arrived changed");
    let file =
        sftp.open_file(&home.join("up.bin").to_string_lossy(), OpenFlags::READ, FileAttributes::empty()).await.unwrap();
    let mut back = Vec::new();
    while let Some(part) = sftp.read(&file, back.len() as u64, sftp.read_len()).await.unwrap() {
        back.extend_from_slice(&part);
    }
    sftp.close(&file).await.unwrap();
    assert_eq!(digest(&back), digest(&sent), "the file came back changed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_step_of_a_session_works_on_the_paths_given() {
    let home = scratch("steps");
    std::fs::write(home.join("a.txt"), b"A").unwrap();
    std::fs::write(home.join("b.txt"), b"B").unwrap();
    let handle = connect(settings(&home)).await;
    let sftp = sftp(&handle).await;
    assert_eq!(PathBuf::from(sftp.realpath(".").await.unwrap()), home);
    sftp.mkdir("dir", FileAttributes { permissions: Some(0o750), ..FileAttributes::empty() }).await.unwrap();
    // The mode asked for, under the process's umask.
    let mode = std::fs::metadata(home.join("dir")).unwrap().permissions().mode() & 0o777;
    assert!(mode & !0o750 == 0 && mode & 0o700 == 0o700, "{mode:o}");
    // Over an existing name: posix-rename@openssh.com.
    sftp.rename("a.txt", "b.txt").await.unwrap();
    assert_eq!(std::fs::read(home.join("b.txt")).unwrap(), b"A");
    sftp.rename("b.txt", "dir/c.txt").await.unwrap();
    sftp.symlink("dir/link", "c.txt").await.unwrap();
    assert_eq!(sftp.readlink("dir/link").await.unwrap(), "c.txt");
    assert_eq!(sftp.stat("dir/link").await.unwrap().size, Some(1));
    assert!(sftp.lstat("dir/link").await.unwrap().is_symlink());
    let mut names: Vec<String> = sftp.read_dir("dir").await.unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec![".", "..", "c.txt", "link"]);
    let listed = sftp.read_dir("dir").await.unwrap();
    let line = &listed.iter().find(|e| e.name == "c.txt").unwrap().longname;
    assert!(line.starts_with("-rw") && line.ends_with(" c.txt"), "{line}");
    sftp.setstat(
        "dir/c.txt",
        FileAttributes { mtime: Some(1_000_000_000), atime: Some(1_000_000_000), ..FileAttributes::empty() },
    )
    .await
    .unwrap();
    assert_eq!(sftp.stat("dir/c.txt").await.unwrap().mtime, Some(1_000_000_000));
    sftp.remove("dir/link").await.unwrap();
    sftp.remove("dir/c.txt").await.unwrap();
    sftp.rmdir("dir").await.unwrap();
    assert!(!home.join("dir").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_refusal_has_its_code_and_its_words() {
    let home = scratch("refusals");
    let handle = connect(settings(&home)).await;
    let sftp = sftp(&handle).await;
    let missing = sftp.stat("absent").await.unwrap_err();
    assert!(missing.is_missing(), "{missing:?}");
    let SftpError::Status { message, .. } = &missing else { panic!("{missing:?}") };
    assert!(message.contains("absent") && message.contains("No such file"), "{message}");
    std::fs::write(home.join("x"), b"x").unwrap();
    std::fs::create_dir(home.join("full")).unwrap();
    std::fs::write(home.join("full/f"), b"f").unwrap();
    let busy = sftp.rmdir("full").await.unwrap_err();
    assert!(matches!(busy, SftpError::Status { code: 4, .. }), "{busy:?}");
    // SAFETY: geteuid has no precondition.
    if unsafe { libc::geteuid() } != 0 {
        std::fs::set_permissions(home.join("x"), std::fs::Permissions::from_mode(0o0)).unwrap();
        let denied = sftp.open_file("x", OpenFlags::READ, FileAttributes::empty()).await.unwrap_err();
        assert!(matches!(denied, SftpError::Status { code: 3, .. }), "{denied:?}");
    }
    // An extension that the server does not name.
    let other = sftp.hardlink("x", "y").await.unwrap_err();
    assert!(matches!(other, SftpError::Status { code: 8, .. }), "{other:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_open_handles_are_bounded() {
    let home = scratch("handles");
    std::fs::write(home.join("f"), b"f").unwrap();
    let handle = connect(settings(&home)).await;
    let sftp = sftp(&handle).await;
    let mut open = Vec::new();
    for _ in 0..MAX_HANDLES {
        open.push(sftp.open_file("f", OpenFlags::READ, FileAttributes::empty()).await.unwrap());
    }
    // podssh's client reads the bound of `limits@openssh.com` and refuses
    // the 257th itself; another client gets the server's own refusal
    // (`the_handles_are_bounded_and_a_close_makes_room`, in the server's tests).
    let refused = sftp.open_file("f", OpenFlags::READ, FileAttributes::empty()).await.unwrap_err();
    match &refused {
        SftpError::Status { code: 4, message, .. } => assert!(message.contains("256"), "{message}"),
        other => assert!(format!("{other:?}").contains("handle limit"), "{other:?}"),
    }
    sftp.close(&open.remove(0)).await.unwrap();
    sftp.open_file("f", OpenFlags::READ, FileAttributes::empty()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fifo_with_no_writer_fails_within_the_limit_and_the_session_goes_on() {
    let home = scratch("fifo");
    let fifo = std::ffi::CString::new(home.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid C string.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let limit = Duration::from_secs(1);
    let handle = connect(Settings { sftp_limit: Some(limit), ..settings(&home) }).await;
    let sftp = sftp(&handle).await;
    let started = Instant::now();
    let stuck = sftp.open_file("fifo", OpenFlags::READ, FileAttributes::empty()).await.unwrap_err();
    let waited = started.elapsed();
    let SftpError::Status { code: 4, message, .. } = &stuck else { panic!("{stuck:?}") };
    assert!(message.contains("no answer within"), "{message}");
    assert!(waited < limit + Duration::from_secs(5), "{waited:?}");
    assert_eq!(PathBuf::from(sftp.realpath("").await.unwrap()), home, "the session goes on");
}
