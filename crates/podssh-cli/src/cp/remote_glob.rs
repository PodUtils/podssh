//! A remote source whose last name holds `*` or `?` (T-828): the names of
//! its directory that it matches, in their order, over the link's SFTP, as
//! OpenSSH's scp lets the far shell expand them and as `podssh sftp`'s `get`
//! does. A name that starts with `.` is matched only by a pattern that does.
//! A pattern that matches nothing is a missing source (66). A copy by exec,
//! with no SFTP, takes the path as it is.

use super::link::Link;
use super::operand::{Operand, Remote};
use super::transfer::{self, Failed, Side};
use crate::exitmap::Fault;
use crate::sftp::commands;

/// `sources`, each remote pattern in place of the paths that it matches.
pub(super) async fn expanded(link: &Option<Link>, sources: &[Operand]) -> Result<Vec<Operand>, Failed> {
    let Some(sftp) = super::tree_copy::sftp_of(link) else { return Ok(sources.to_vec()) };
    let mut out = Vec::with_capacity(sources.len());
    for source in sources {
        let Operand::Remote(remote) = source else {
            out.push(source.clone());
            continue;
        };
        if !commands::is_pattern(&remote.path) {
            out.push(source.clone());
            continue;
        }
        let (dir, pattern) = transfer::split_remote(&remote.path);
        let listed = sftp
            .read_dir(if dir.is_empty() { "." } else { dir })
            .await
            .map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let mut found: Vec<String> = listed
            .into_iter()
            .map(|e| e.name)
            .filter(|name| taken(pattern, name))
            .map(|n| format!("{dir}{n}"))
            .collect();
        found.sort();
        if found.is_empty() {
            return Err(Failed::new(Fault::NoInput, format!("{}: no file matches", remote.path)));
        }
        out.extend(found.into_iter().map(|path| Operand::Remote(Remote { path, ..remote.clone() })));
    }
    Ok(out)
}

/// Whether `pattern` takes `name`: never `.` or `..`, and a hidden name
/// only by a pattern that is hidden too, as a shell's glob.
fn taken(pattern: &str, name: &str) -> bool {
    let hidden = name.starts_with('.') && !pattern.starts_with('.');
    name != "." && name != ".." && !hidden && commands::matches(pattern, name)
}

#[cfg(test)]
mod tests {
    use super::taken;

    #[test]
    fn a_pattern_takes_names_as_a_shell_does() {
        assert!(taken("big*", "big1") && taken("b?g2", "big2") && taken("*", "f.txt"));
        assert!(!taken("*", ".hidden") && taken(".*", ".hidden"));
        assert!(!taken(".*", ".") && !taken(".*", ".."));
        assert!(!taken("*.conf", "a.txt"));
    }
}
