//! Where several sources go (T-935): into a directory, which must be there.
//! The destination is looked at once, before the first source goes, so that
//! a destination that is a file, or is missing, is said once with its true
//! reason, and not once for each source.

use super::byexec::Kind;
use super::link::{Link, Road};
use super::operand::Operand;
use super::transfer::Failed;
use super::words::said;
use crate::exitmap::Fault;

/// The failure of `dest` for several sources: missing, or not a directory.
pub(crate) fn not_into(dest: &str, missing: bool) -> Failed {
    let what = if missing { "no such directory" } else { "not a directory" };
    Failed::new(Fault::CantCreate, format!("{dest}: {what}, and there are several sources"))
}

/// Whether `dest` can take several sources: `None` when it is a directory,
/// or when the look itself fails (each source then says its own failure).
pub(super) async fn several(link: Option<&Link>, dest: &Operand) -> Option<Failed> {
    match dest {
        Operand::Local(path) => match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => None,
            Ok(_) => Some(not_into(path, false)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(not_into(path, true)),
            Err(e) => Some(Failed::new(Fault::CantCreate, format!("{path}: {}", said(&e)))),
        },
        Operand::Remote(remote) => {
            // The login directory, and the root, are directories.
            if remote.path.trim_end_matches('/').is_empty() {
                return None;
            }
            let link = link?;
            match &link.road {
                Road::Sftp(sftp) => match sftp.stat(&remote.path).await {
                    Ok(attrs) if attrs.is_dir() => None,
                    Ok(_) => Some(not_into(&remote.path, false)),
                    Err(e) if e.is_missing() => Some(not_into(&remote.path, true)),
                    Err(_) => None,
                },
                Road::Exec(far) => match far.kind(link.handle(), &remote.path).await {
                    Ok(Kind::Dir) | Err(_) => None,
                    Ok(Kind::Missing) => Some(not_into(&remote.path, true)),
                    Ok(_) => Some(not_into(&remote.path, false)),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_destination_for_several_sources_says_its_true_reason() {
        let dir = std::env::temp_dir().join(format!("podssh-into-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        let shown = |name: &str| dir.join(name).display().to_string();
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let look = |name: &str| rt.block_on(several(None, &Operand::Local(shown(name))));
        assert_eq!(look(""), None, "a directory takes them");
        let file = look("file").expect("a file takes no several sources");
        assert_eq!(file.fault, Fault::CantCreate);
        assert!(file.message.ends_with("file: not a directory, and there are several sources"), "{}", file.message);
        let missing = look("missing").expect("a missing directory");
        assert!(missing.message.contains("missing: no such directory"), "{}", missing.message);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
