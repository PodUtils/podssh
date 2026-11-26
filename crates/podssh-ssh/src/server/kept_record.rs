//! The record of the kept shells' names (T-159): a private file, one line
//! for each kept shell, the fingerprint of its key and its name. A restart
//! of `podssh serve`, or of its host, ends each kept shell, as a process
//! does not outlive either; the next start reads the record and says what
//! was lost. The record holds names alone, never output.
//!
//! The file is replaced whole: a new file of a unique name beside it, mode
//! 0600, then a rename over it. Its name holds random bits, not a pid,
//! which is not unique across PID namespaces.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The longest record that a start reads: 32 lines fit in 4 KiB.
const LONGEST: u64 = 64 * 1024;

/// The names of `path`, each with its key: none where there is no file.
/// A line that is not a fingerprint and a name is passed over.
pub(super) fn read(path: &Path) -> Result<Vec<(String, String)>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {}", path.display(), podssh_ws::text::said(&e))),
    };
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.len() > LONGEST {
        return Err(format!("{}: longer than {LONGEST} bytes, which no record is", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))?;
    Ok(parse(&String::from_utf8_lossy(&bytes)))
}

/// The lines of a record: `FINGERPRINT NAME` each.
pub(super) fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (owner, name) = (words.next()?, words.next()?);
            let good = words.next().is_none() && crate::keep::check_name(name).is_ok();
            good.then(|| (owner.to_string(), name.to_string()))
        })
        .collect()
}

/// Replace the record at `path` with `names`.
pub(super) fn write(path: &Path, names: &[(String, String)]) -> io::Result<()> {
    let mut text = String::new();
    for (owner, name) in names {
        text.push_str(owner);
        text.push(' ');
        text.push_str(name);
        text.push('\n');
    }
    let fresh = beside(path)?;
    let written = write_new(&fresh, text.as_bytes()).and_then(|()| std::fs::rename(&fresh, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&fresh);
    }
    written
}

/// A new name beside `path`: `.NAME.` and 64 random bits in hex.
fn beside(path: &Path) -> io::Result<PathBuf> {
    let mut bits = [0u8; 8];
    aws_lc_rs::rand::fill(&mut bits).map_err(|_| io::Error::other("the system gave no random bytes"))?;
    let file = path.file_name().ok_or_else(|| io::Error::other("the record's path names no file"))?;
    let mut name = std::ffi::OsString::from(".");
    name.push(file);
    name.push(format!(".{:016x}", u64::from_le_bytes(bits)));
    Ok(path.with_file_name(name))
}

/// Make `path`, which must not be there, with `bytes`, mode 0600.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record's lines: a fingerprint and a name; each other line is
    /// passed over, as a record that another program changed.
    #[test]
    fn a_record_holds_a_fingerprint_and_a_name_on_each_line() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            ("SHA256:abc work\n", &[("SHA256:abc", "work")]),
            ("SHA256:abc work\nSHA256:def build-2\n", &[("SHA256:abc", "work"), ("SHA256:def", "build-2")]),
            ("SHA256:abc\n", &[]),
            ("SHA256:abc work extra\n", &[]),
            ("SHA256:abc ../x\n", &[]),
            ("\n\n", &[]),
        ];
        for (text, want) in cases {
            let got = parse(text);
            let want: Vec<(String, String)> = want.iter().map(|(o, n)| (o.to_string(), n.to_string())).collect();
            assert_eq!(got, want, "{text:?}");
        }
    }

    /// The record is replaced whole, mode 0600, and read back; none is
    /// no name. Its directory is removed at the end.
    #[test]
    fn a_record_is_written_whole_and_read_back() {
        let mut bits = [0u8; 8];
        aws_lc_rs::rand::fill(&mut bits).unwrap();
        let dir = std::env::temp_dir().join(format!("podssh-kept-{:016x}", u64::from_le_bytes(bits)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("serve-lab.kept");
        let read_back = read(&path);
        let names = vec![("SHA256:abc".to_string(), "work".to_string())];
        let written = write(&path, &names);
        let again = read(&path);
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777).ok()
        };
        let leftover = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_back, Ok(Vec::new()), "no file, no name");
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(again, Ok(names));
        assert_eq!(leftover, 1, "no file of a write is left beside the record");
        #[cfg(unix)]
        assert_eq!(mode, Some(0o600));
    }
}
