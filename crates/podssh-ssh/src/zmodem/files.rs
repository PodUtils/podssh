//! The local side of a transfer. A name that the server offers is checked
//! before anything is written: its last component only, which must be one
//! that may be written here, as T-143 checks the names of a far listing. A
//! file comes as T-134 writes a copy: into `.NAME.podssh-RANDOM.part` beside
//! it, made new with mode 0600; once its length is checked, it gets its
//! time and its mode, and a rename gives it its name. A transfer that ends
//! before that removes the temporary file, and a name that is taken is
//! replaced only when the user said so. The 7-bit envelope (T-831) writes
//! its copies the same way, and reads the file it sends here too.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::receive::Offer;

/// The names that Windows keeps for devices, with or without an extension.
const DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The name to write for a path that the server offers: its last
/// component, when it may be written here. `sz` sends the file's name
/// alone, and with `-f` its whole path.
pub fn check_name(offered: &str) -> Result<String, String> {
    let name = offered.rsplit('/').next().unwrap_or_default();
    let shown = podssh_ws::text::one_line(offered);
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("{shown:?} names no file"));
    }
    if name.chars().any(char::is_control) {
        return Err(format!("{shown:?} holds a control character"));
    }
    if cfg!(windows) {
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.contains(['\\', ':', '<', '>', '"', '|', '?', '*']) {
            return Err(format!("{shown:?} holds a character that a Windows file name cannot"));
        }
        if DEVICES.contains(&stem.as_str()) {
            return Err(format!("{shown:?} is the name of a Windows device"));
        }
        if name.ends_with(['.', ' ']) {
            return Err(format!("{shown:?} ends with a dot or a space, which Windows drops"));
        }
    }
    Ok(name.to_string())
}

/// `.NAME.podssh-RANDOM.part`: hidden, unique, and named for what it holds.
pub fn temp_name(name: &str) -> String {
    format!(".{name}.podssh-{:016x}.part", rand::random::<u64>())
}

/// A file that comes, under its temporary name until it is whole.
#[derive(Debug)]
pub struct Incoming {
    pub name: String,
    pub dest: PathBuf,
    /// Empty once the file has its name, or is kept under this one.
    temp: PathBuf,
    out: Option<BufWriter<File>>,
    size: Option<u64>,
    mtime: Option<u64>,
    mode: Option<u32>,
    /// The user let a file of that name go.
    replace: bool,
    written: u64,
}

impl Incoming {
    /// The temporary file for `name` in `dir`, made new with mode 0600.
    pub fn create(dir: &Path, name: &str, offer: &Offer, replace: bool) -> std::io::Result<Incoming> {
        let temp = dir.join(temp_name(name));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&temp)?;
        Ok(Incoming {
            name: name.to_string(),
            dest: dir.join(name),
            temp,
            out: Some(BufWriter::with_capacity(64 * 1024, file)),
            size: offer.size,
            mtime: offer.mtime,
            mode: offer.mode,
            replace,
            written: 0,
        })
    }

    /// Where the bytes go until the rename.
    pub fn temp(&self) -> &Path {
        &self.temp
    }

    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let out = self.out.as_mut().ok_or_else(|| std::io::Error::other("the file is closed"))?;
        out.write_all(data)?;
        self.written += data.len() as u64;
        Ok(())
    }

    /// The whole file came, `length` bytes by ZEOF: the length must be what
    /// was written and what ZFILE said. Then the file gets the server's time
    /// and mode, and its name. A name that was taken meanwhile is not
    /// replaced: the file stays under its temporary name, which the error
    /// gives.
    pub fn finish(&mut self, length: u64) -> Result<PathBuf, String> {
        let out = self.out.take().ok_or_else(|| format!("{}: the file is closed", self.name))?;
        let file = out.into_inner().map_err(|e| format!("{}: {}", self.name, e.error()))?;
        if self.written != length || self.size.is_some_and(|size| size != length) {
            let said = self.size.map_or(String::new(), |size| format!(", and ZFILE said {size}"));
            return Err(format!(
                "{}: {} bytes came, ZEOF said {length}{said}; nothing was kept",
                self.name, self.written
            ));
        }
        file.sync_all().map_err(|e| format!("{}: {e}", self.name))?;
        if let Some(seconds) = self.mtime {
            // A file system that cannot keep the server's time keeps its own.
            let _ = file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds));
        }
        drop(file);
        if let Some(mode) = self.mode {
            // The server's permission bits, with no write for the group and
            // others, and no set-id bits.
            set_mode(&self.temp, mode & 0o755);
        }
        if !self.replace && std::fs::symlink_metadata(&self.dest).is_ok() {
            let kept = std::mem::take(&mut self.temp);
            return Err(format!(
                "{} appeared while the file came, and was not replaced; the file is {}",
                self.dest.display(),
                kept.display()
            ));
        }
        std::fs::rename(&self.temp, &self.dest).map_err(|e| format!("{}: {e}", self.dest.display()))?;
        self.temp = PathBuf::new();
        Ok(self.dest.clone())
    }
}

impl Drop for Incoming {
    /// A file that did not end goes, as T-134's failure removes its
    /// temporary file.
    fn drop(&mut self) {
        self.out = None;
        if !self.temp.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// Windows keeps its own access list.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// A file to send, and what ZFILE says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub name: String,
    pub size: u64,
    /// Seconds since 1970.
    pub mtime: u64,
    /// The file's type and permission bits, as `st_mode`; 0 on Windows.
    pub mode: u32,
}

impl Outgoing {
    /// ZFILE's data (the spec's section 13): the name and a NUL, then the
    /// length in decimal, the time and the mode in octal, the serial number
    /// 0, the files left (1, this one) and the bytes left, then a NUL. lrzsz's
    /// `sz` writes the same fields.
    pub fn zfile(&self) -> Vec<u8> {
        let mut data = self.name.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(format!("{} {:o} {:o} 0 1 {}", self.size, self.mtime, self.mode, self.size).as_bytes());
        data.push(0);
        data
    }
}

/// The file at `path` to send: a regular file that opens, under 4 GiB, as
/// the spec's positions have 32 bits.
pub fn open(path: &Path) -> Result<(File, Outgoing), String> {
    let shown = path.display();
    let file = File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.len() > u64::from(u32::MAX) {
        return Err(format!("{shown}: ZMODEM carries files under 4 GiB"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("{shown} names no file"))?;
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    Ok((file, Outgoing { name, size: meta.len(), mtime, mode: mode_of(&meta) }))
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    // A regular file and its permission bits, as lrzsz's `sz` sends `st_mode`.
    0o100000 | (meta.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// The file at `path` that the 7-bit envelope sends (T-831): a regular file
/// that opens, of any size below 2^63, as its offsets have 64 bits.
pub fn open_whole(path: &Path) -> Result<(File, pod_term::transfer::FileInfo), String> {
    let shown = path.display();
    let file = File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("{shown} names no file"))?;
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
    // The permission bits alone: the type of the file is the codec's to say.
    let mode = Some(mode_of(&meta) & 0o7777).filter(|&m| m != 0);
    let info = pod_term::transfer::FileInfo { name, size: meta.len(), mode, mtime: mtime.filter(|&s| s > 0) };
    Ok((file, info))
}

/// `buf.len()` bytes of `file` at `offset`, fewer only at its end: a short
/// read is no end.
pub fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(read) => n += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// The line for a copy that could not be started in `dir`. The error names
/// the temporary file, a name that nobody typed, and in a directory that
/// exists but takes no file (`/proc`) it can say "No such file".
pub fn cannot_create(dir: &Path, error: &std::io::Error) -> String {
    format!("a file could not be created in {}: {error}", podssh_ws::text::one_line(&dir.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line names the directory and the system's words, and never the
    /// temporary name of the copy.
    #[test]
    fn a_copy_that_cannot_start_names_the_directory() {
        let dir = Path::new("/nonexistent-podssh-dir");
        let offer = Offer { name: "up.bin".into(), size: Some(1), mtime: None, mode: None };
        let Err(error) = Incoming::create(dir, "up.bin", &offer, false) else { return };
        let line = cannot_create(dir, &error);
        assert!(line.starts_with("a file could not be created in /nonexistent-podssh-dir: "), "{line}");
        assert!(line.ends_with(&error.to_string()) && !line.contains(".part"), "{line}");
    }
}
