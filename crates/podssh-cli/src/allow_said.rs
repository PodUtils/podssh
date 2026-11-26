//! The lines of a node's allowlist that are not keys (T-1025). The node
//! says them as it starts (`channel::who_may`), and its allowlist is read
//! again for each session (T-089). A re-read that finds another set of such
//! lines says it once, so that a file edited while the node serves is never
//! half read in silence; the same set is not said again.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use podssh_relay::identity::{allow, PublicKey};
use podssh_relay::reverse::routes::Grant;

/// The set of lines that are not keys, last said for each allowlist.
static SAID: Mutex<Vec<(PathBuf, Vec<usize>)>> = Mutex::new(Vec::new());

/// The words of `lines` of `path`, kept as said: the node's line at its
/// start.
pub fn marked(path: &Path, lines: &[usize]) -> String {
    let _ = seen(path, lines);
    allow::bad_lines_said(lines)
}

/// The line to say when the lines of `path` that are not keys differ from
/// those said last, with the file's name; `None` when they are the same, or
/// when none is left (a file put right says nothing).
pub fn seen(path: &Path, lines: &[usize]) -> Option<String> {
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    let at = said.iter().position(|(file, _)| file.as_path() == path);
    // A file not read before had no such line said.
    let before: &[usize] = at.map(|i| said[i].1.as_slice()).unwrap_or(&[]);
    if before == lines {
        return None;
    }
    match at {
        Some(i) => said[i].1 = lines.to_vec(),
        None => said.push((path.to_path_buf(), lines.to_vec())),
    }
    (!lines.is_empty()).then(|| format!("{}: {}", path.display(), allow::bad_lines_said(lines)))
}

/// Which routes each operator may use (T-089): those that its line of the
/// allowlist at `allow` grants, read again for each session; with no
/// allowlist, each route, as the relay's connect token decided who reaches
/// the node. A re-read that finds new lines that are not keys says them.
pub fn grant_of(allow: Option<PathBuf>) -> Arc<Grant> {
    match allow {
        Some(path) => Arc::new(move |key: &PublicKey, route: &str| {
            if let Some(line) = allow::read(&path).ok().and_then(|list| seen(&path, list.bad_lines())) {
                podssh_ssh::err_line!("podssh node: {line}");
            }
            allow::grants(&path, key, route)
        }),
        None => Arc::new(|_: &PublicKey, _: &str| Ok(())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each read of one file, in order: (the lines that are not keys, said).
    #[test]
    fn a_set_of_lines_that_are_not_keys_is_said_once_until_it_changes() {
        let path = std::env::temp_dir().join(format!("podssh-allow-said-{}", std::process::id()));
        assert_eq!(marked(&path, &[2]), allow::bad_lines_said(&[2]), "the start's words");
        let reads: [(&[usize], bool); 6] = [
            (&[2][..], false),
            (&[2, 5][..], true),
            (&[2, 5][..], false),
            (&[][..], false),
            (&[][..], false),
            (&[2][..], true),
        ];
        for (at, (lines, said)) in reads.iter().enumerate() {
            let line = seen(&path, lines);
            assert_eq!(line.is_some(), *said, "read {at}: {lines:?}");
            if let Some(line) = line {
                assert!(line.starts_with(&format!("{}: lines ", path.display())), "{line}");
            }
        }
        // A file that the start found right says nothing on a re-read alike.
        let other = path.with_extension("other");
        assert_eq!(seen(&other, &[]), None);
        assert!(seen(&other, &[1]).is_some());
    }
}
