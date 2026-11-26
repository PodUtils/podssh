//! `podssh job fetch HOST ID [DIR]` (T-197): the output of a job that
//! ended, and the files that `--files` names in the home directory of the
//! host, each copied as `podssh cp` copies a file (over SFTP, or by exec; a
//! temporary name, the digests, a rename; a new connection after a break),
//! into DIR, `./podssh-job-ID` by default. The output is `DIR/out`, and each
//! file goes under `DIR/files` by its path from the home directory, so that
//! no name of the host takes the place of the output.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::{Log, EXIT_FAILURE};

use super::{far, first_line, unexpected};
use crate::cp::link;
use crate::cp::operand::{Operand, Remote};
use crate::cp::pipe::Shape;
use crate::cp::session;
use crate::cp::words::said;
use crate::exitmap::{sysexits, Fault};
use crate::ssh::resolve::Resolved;

/// What the far script said of a job to fetch: the name of its directory,
/// its state, and each file that the pattern names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub dir: String,
    pub state: String,
    pub files: Vec<String>,
}

/// The answer of the far script's `files`: `dir NAME STATE`, a line
/// `file PATH` for each file, then `end`; `None` for another answer, or one
/// that did not end.
pub fn parse_found(lines: &[String]) -> Option<Found> {
    let (head, rest) = lines.split_first()?;
    let mut words = head.split(' ');
    if words.next()? != "dir" {
        return None;
    }
    let (dir, state) = (words.next()?.to_string(), words.next()?.to_string());
    if rest.last().map(String::as_str) != Some("end") {
        return None;
    }
    let files = rest.iter().filter_map(|l| l.strip_prefix("file ")).map(str::to_string).collect();
    Some(Found { dir, state, files })
}

/// The place here of a far file of `--files`: under `dir/files`, by its
/// path from the home directory, each part a name that may be written
/// here; `None` for a path that has no such place.
pub fn local_place(dir: &Path, far: &str) -> Option<PathBuf> {
    let root = dir.join("files");
    let mut place = root.clone();
    for part in far.split('/').filter(|p| !p.is_empty() && *p != ".") {
        crate::cp::tree::check_name(part, cfg!(windows)).ok()?;
        place.push(part);
    }
    (place != root).then_some(place)
}

/// The directories that a fetch made here for DIR, the deepest last, so
/// that a fetch that brought nothing takes them away again (T-1065).
#[derive(Debug, Default)]
pub struct Made(Vec<PathBuf>);

impl Made {
    /// Remove each directory that this fetch made and that is still empty,
    /// the deepest first: one that holds a file, put there by this fetch or
    /// by another process, stays, and so does each above it.
    pub fn undo(self) {
        for dir in self.0.iter().rev() {
            if std::fs::remove_dir(dir).is_err() {
                break;
            }
        }
    }
}

/// Make DIR here before anything connects (T-1065): a DIR that cannot be
/// made, or that is no directory, is a fault here (73), as the destination
/// of `podssh cp` is, and never reads as a host out of reach (255).
pub fn prepare(dir: &Path) -> Result<Made, String> {
    // The levels of DIR that are not there, from DIR up.
    let mut missing = Vec::new();
    let mut at = Some(dir).filter(|p| !p.as_os_str().is_empty());
    while let Some(path) = at {
        match std::fs::symlink_metadata(path) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(path.to_path_buf());
                at = path.parent().filter(|p| !p.as_os_str().is_empty());
            }
            Err(e) => return Err(format!("{}: {}", path.display(), said(&e))),
        }
    }
    let mut made = Made::default();
    for path in missing.into_iter().rev() {
        match std::fs::create_dir(&path) {
            Ok(()) => made.0.push(path),
            // Another process made it in the meantime: it is not ours.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {}
            Err(e) => {
                made.undo();
                return Err(format!("{}: cannot be made here: {}", path.display(), said(&e)));
            }
        }
    }
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(made),
        Ok(_) => Err(format!("{}: not a directory, so the job's output has no place there", dir.display())),
        Err(e) => {
            made.undo();
            Err(format!("{}: {}", dir.display(), said(&e)))
        }
    }
}

/// Fetch the job `id` into `dir`: 0; 73 when DIR, or a file under it,
/// cannot be made here (T-1065); 255 when the host, or a copy of a file of
/// the host, failed; 75 when the job has not ended, so that its output is
/// not whole yet. A lost job (no status, and nothing runs it) gives what it
/// wrote, then 255 with a line, as `wait` and `log --follow` end for it
/// (T-986). The directories that it made and left empty go again.
pub(crate) async fn fetch(
    resolved: &Resolved,
    host: &str,
    id: &str,
    dir: &Path,
    files: Option<&str>,
    log: &Arc<Log>,
) -> i32 {
    let made = match prepare(dir) {
        Ok(made) => made,
        Err(why) => {
            log.error(&why);
            return sysexits::EX_CANTCREAT;
        }
    };
    let code = fetch_into(resolved, host, id, dir, files, log).await;
    if code != 0 {
        made.undo();
    }
    code
}

/// [`fetch`] into a DIR that is there.
async fn fetch_into(
    resolved: &Resolved,
    host: &str,
    id: &str,
    dir: &Path,
    files: Option<&str>,
    log: &Arc<Log>,
) -> i32 {
    let first = match link::connect(resolved, log).await {
        Ok(first) => first,
        Err(failed) => {
            log.error(&failed.message);
            return EXIT_FAILURE;
        }
    };
    let found = match far::lines(first.handle(), host, &["files", id, files.unwrap_or("-")]).await {
        Ok(lines) => {
            first_line(host, &lines).and_then(|head| parse_found(&lines).ok_or_else(|| unexpected(host, head)))
        }
        Err(why) => Err(why),
    };
    let found = match found {
        Ok(found) => found,
        Err(why) => {
            first.close().await;
            log.error(&why);
            return EXIT_FAILURE;
        }
    };
    if found.state == "queued" || found.state == "running" {
        first.close().await;
        log.error(&format!(
            "job {id} on {host} is {}, so its output is not whole yet; podssh job wait {host} {id} waits for its end",
            found.state
        ));
        return sysexits::EX_TEMPFAIL;
    }
    let mut copies = vec![(format!(".podssh/jobs/{}/out", found.dir), dir.join("out"))];
    // A fault here (73) and a fault of the host or of the link (255), apart.
    let (mut here, mut far_failed) = (false, false);
    for far in &found.files {
        match local_place(dir, far) {
            Some(place) => copies.push((far.clone(), place)),
            None => {
                here = true;
                log.error(&format!("{far}: not copied: its path has no place under {}", dir.join("files").display()));
            }
        }
    }
    let mut link = Some(first);
    for (far, place) in copies {
        if let Some(parent) = place.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                here = true;
                log.error(&format!("{}: cannot be made here: {}", parent.display(), said(&e)));
                continue;
            }
        }
        let source =
            Operand::Remote(Remote { user: None, host: host.to_string(), port: None, path: far.clone(), node: false });
        let dest = Operand::Local(place.display().to_string());
        match session::attempts(&mut link, resolved, &source, &dest, false, log, Shape::default()).await {
            Ok((done, _)) => log.verbose(&format!("{far}: {} bytes to {}", done.bytes, done.destination)),
            Err(f) => {
                // The destination is here: cp's fault of a destination is ours.
                match f.fault {
                    Fault::CantCreate => here = true,
                    _ => far_failed = true,
                }
                log.error(&f.message);
                // No connection is left for the next file.
                if link.is_none() {
                    break;
                }
            }
        }
    }
    if let Some(link) = link {
        link.close().await;
    }
    if found.state == "lost" {
        log.error(&lost_line(id, host, dir));
        return EXIT_FAILURE;
    }
    exit_of(here, far_failed)
}

/// The exit of a fetch of a job that ended: a fault of the host or of the
/// link first (255), as it can leave the files here unwritten too; then a
/// fault here alone (73); else 0.
pub fn exit_of(here: bool, far_failed: bool) -> i32 {
    match (here, far_failed) {
        (_, true) => EXIT_FAILURE,
        (true, false) => sysexits::EX_CANTCREAT,
        (false, false) => 0,
    }
}

/// The line of a fetch of a lost job: what was copied is what it wrote
/// before it was lost, and it has no status (T-986).
pub fn lost_line(id: &str, host: &str, dir: &Path) -> String {
    format!(
        "job {id} on {host} is lost (no status, and nothing runs it): {} holds what it wrote before",
        dir.join("out").display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_names_the_directory_the_state_and_each_file() {
        let lines: Vec<String> = ["dir 0001-abcd1234 done", "file build/a.log", "file b c.txt", "end"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let found = parse_found(&lines).unwrap();
        assert_eq!((found.dir.as_str(), found.state.as_str()), ("0001-abcd1234", "done"));
        assert_eq!(found.files, ["build/a.log", "b c.txt"]);
        assert_eq!(parse_found(&lines[..3]), None, "no end: the answer was cut");
        assert_eq!(parse_found(&["no-job abcd1234".to_string()]), None);
    }

    #[test]
    fn a_lost_job_is_named_with_what_was_fetched() {
        let line = lost_line("abcd1234", "web1", Path::new("podssh-job-abcd1234"));
        assert!(line.starts_with("job abcd1234 on web1 is lost"), "{line}");
        assert!(line.contains(&Path::new("podssh-job-abcd1234").join("out").display().to_string()), "{line}");
    }

    /// T-1065: DIR is made before anything connects; a DIR that is a file,
    /// or that is under one, is a line that names it here, and nothing is
    /// made; what a fetch made goes again while it is empty, never a
    /// directory that was there or one that holds a file.
    #[test]
    fn a_dir_here_is_made_first_and_its_fault_is_said_here() {
        let root = std::env::temp_dir().join(format!("podssh-fetch-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        for (dir, says) in [(file.clone(), "not a directory"), (file.join("sub"), "a-file")] {
            let why = prepare(&dir).expect_err("no place for DIR");
            assert!(why.contains(says), "{}: {why}", dir.display());
            assert!(!why.contains("(os error"), "{why}");
            assert!(std::fs::read(&file).is_ok_and(|b| b == b"x"), "the file stays as it was");
        }
        let deep = root.join("new").join("deeper");
        let made = prepare(&deep).unwrap();
        assert!(deep.is_dir());
        made.undo();
        assert!(!root.join("new").exists(), "the two levels that the fetch made go again");
        let made = prepare(&deep).unwrap();
        std::fs::write(deep.join("out"), b"x").unwrap();
        made.undo();
        assert!(deep.join("out").is_file(), "a directory that holds a file stays");
        prepare(&root).unwrap().undo();
        assert!(root.is_dir(), "a directory that was there is never removed");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The exit of a fetch: a fault of the host first, then one here.
    #[test]
    fn a_fault_here_is_73_and_one_of_the_host_is_255() {
        for (here, far, code) in [(false, false, 0), (true, false, 73), (false, true, 255), (true, true, 255)] {
            assert_eq!(exit_of(here, far), code, "here {here}, far {far}");
        }
    }

    #[test]
    fn a_far_file_goes_under_files_and_never_out_of_it() {
        let dir = Path::new("podssh-job-abcd1234");
        assert_eq!(local_place(dir, "build/a.log"), Some(dir.join("files").join("build").join("a.log")));
        assert_eq!(local_place(dir, "./out"), Some(dir.join("files").join("out")), "never the output");
        for bad in ["../x", "a/../../x", "", "."] {
            assert_eq!(local_place(dir, bad), None, "{bad}");
        }
    }
}
