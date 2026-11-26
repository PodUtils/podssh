//! The files that the role writes as it serves (`--pairs`, `--usage`),
//! checked as it starts (T-1014): a directory that is not there, or that
//! this user cannot write, stops the start (78), where it would otherwise
//! answer each later pair with 503 and the path.

use std::fs::OpenOptions;
use std::path::Path;

use crate::relay_settings::Refusal;

/// Whether `path`, the file of `flag`, can be made or replaced: its
/// directory is there, is a directory, and takes a new file of a unique
/// name, which is removed at once. The file itself is no directory.
pub(super) fn writable(flag: &str, path: &str) -> Result<(), Refusal> {
    let file = Path::new(path);
    let fault = |why: String| Refusal::config(format!("{flag} {path}: {why}"));
    let dir = match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(fault(format!("{} is not a directory", dir.display()))),
        Err(e) => return Err(fault(podssh_ws::text::file_said(file, &e))),
    }
    if file.is_dir() {
        return Err(fault("a directory, where the role keeps one file".to_string()));
    }
    // A unique name: a pid is not unique across PID namespaces, and two
    // roles may share the directory.
    let probe = dir.join(format!(".podssh-probe-{:016x}", rand::random::<u64>()));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(fault(format!("{} cannot be written: {}", dir.display(), podssh_ws::text::said(&e)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file in a directory that is not there, under a file, or that is a
    /// directory itself is refused (78) with its flag and path once; a file
    /// of a directory that takes one passes, and nothing is left there.
    #[test]
    fn a_file_whose_directory_cannot_take_it_is_refused() {
        let dir = std::env::temp_dir().join(format!("podssh-files-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain");
        std::fs::write(&plain, "x").unwrap();
        let at = |p: std::path::PathBuf| p.display().to_string();
        let rows = [
            (at(dir.join("gone").join("p.json")), "the directory "),
            (at(plain.join("p.json")), "is not a directory"),
            (at(dir.clone()), "a directory, where the role keeps one file"),
        ];
        for (path, says) in &rows {
            let refusal = writable("--pairs", path).unwrap_err();
            assert_eq!(refusal.code, 78, "{refusal}");
            assert!(refusal.message.starts_with(&format!("--pairs {path}: ")), "{refusal}");
            assert!(refusal.message.contains(says), "{refusal}");
        }
        assert!(writable("--usage", &at(dir.join("counts.json"))).is_ok());
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(Result::ok).map(|e| e.file_name()).collect();
        assert_eq!(left, [std::ffi::OsString::from("plain")], "the probe is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
