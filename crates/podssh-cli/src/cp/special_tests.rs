use super::*;

/// The type bits of a POSIX mode, as SFTP's attributes carry them: a
/// regular file, a directory and a link are none of the kinds.
#[test]
fn a_mode_names_its_kind_and_a_file_a_directory_or_a_link_none() {
    for (mode, want) in [
        (0o100_644, None),
        (0o040_755, None),
        (0o120_777, None),
        (0o000_644, None),
        (0o020_666, Some(Kind::Char)),
        (0o060_660, Some(Kind::Block)),
        (0o010_600, Some(Kind::Fifo)),
        (0o140_755, Some(Kind::Socket)),
    ] {
        assert_eq!(Kind::of_mode(mode), want, "{mode:o}");
    }
}

/// A failure of a copy into a device that broke is an answer, never a
/// continuation: its first bytes went already. Another failure stays.
#[test]
fn a_copy_into_a_device_that_broke_does_not_start_again() {
    let broke = Failed { fault: Fault::SessionFault, message: "the connection broke".into(), cause: Cause::Broke };
    let said = failed(broke, "/dev/null", Kind::Char.what());
    assert_eq!((said.cause, said.fault), (Cause::Answer, Fault::SessionFault));
    let want = "the connection broke; /dev/null is a character device, so the copy into it does not start again";
    assert_eq!(said.message, want);
    let refused = Failed::new(Fault::CantCreate, "/dev/full: No space left on device".into());
    assert_eq!(failed(refused.clone(), "/dev/full", Kind::Char.what()), refused);
}

#[cfg(unix)]
fn fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a path that this test owns, as a C string.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0, "mkfifo {}", path.display());
}

/// Each kind of destination here (T-1038): a regular file, a missing name
/// and a directory are none, which a copy replaces or goes into; a device
/// and a FIFO are written into and stay what they were; a FIFO that no
/// process reads and a socket are refused (73), with no wait.
#[cfg(unix)]
#[test]
fn each_destination_here_is_known_by_its_kind_and_a_device_stays_one() {
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;
    let dir = std::env::temp_dir().join(format!("podssh-special-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"old").unwrap();
    std::fs::create_dir(dir.join("dir")).unwrap();
    fifo(&dir.join("fifo"));
    let _listener = std::os::unix::net::UnixListener::bind(dir.join("socket")).unwrap();
    let null = Path::new("/dev/null");
    for (path, want) in [
        (dir.join("file"), None),
        (dir.join("missing"), None),
        (dir.join("dir"), None),
        (dir.join("fifo"), Some(Kind::Fifo)),
        (dir.join("socket"), Some(Kind::Socket)),
        (null.to_path_buf(), Some(Kind::Char)),
    ] {
        assert_eq!(local(&path), want, "{}", path.display());
    }
    // /dev/null takes the bytes, and stays a character device.
    let mut file = open_local(null, Kind::Char).expect("/dev/null opens to write");
    file.write_all(b"bytes").unwrap();
    ended(file, null, Kind::Char).expect("no fsync of a character device");
    assert!(std::fs::metadata(null).unwrap().file_type().is_char_device());
    // A FIFO that no process reads: said at once.
    let unread = open_local(&dir.join("fifo"), Kind::Fifo).expect_err("no reader");
    assert_eq!(unread.fault.code(), 73, "{}", unread.message);
    assert!(unread.message.ends_with("a FIFO that no process reads; start its reader first"), "{}", unread.message);
    // With a reader, the bytes reach it, and the FIFO stays one.
    let mut reader = std::fs::OpenOptions::new().read(true).write(true).open(dir.join("fifo")).unwrap();
    let mut file = open_local(&dir.join("fifo"), Kind::Fifo).expect("a FIFO with a reader opens");
    file.write_all(b"through").unwrap();
    ended(file, &dir.join("fifo"), Kind::Fifo).unwrap();
    let mut got = [0u8; 7];
    reader.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"through");
    assert!(std::fs::symlink_metadata(dir.join("fifo")).unwrap().file_type().is_fifo(), "never replaced");
    // A socket takes no file's bytes.
    let socket = open_local(&dir.join("socket"), Kind::Socket).expect_err("a socket");
    assert_eq!(socket.fault.code(), 73);
    assert!(socket.message.contains("a socket"), "{}", socket.message);
    let _ = std::fs::remove_dir_all(&dir);
}
