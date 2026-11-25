//! `mv -r` of a directory within one server (T-933): the server renames it,
//! as it renames a file, and no byte moves. Into a directory that is there
//! it goes under its own name, as a file does. A name that is there already
//! is never replaced: `-n` and `-u` leave the source where it is, and with
//! neither the move fails (73), as a rename onto a directory that holds
//! files would. A directory never moves into itself (64).

use podssh_ssh::Log;

use super::byexec::Kind;
use super::clobber::{self, Clobber, Mode, Skip};
use super::link::{Link, Road};
use super::meta::{Keep, Stamp};
use super::moving::{one_file, renamed, stays};
use super::transfer::{self, Done, Failed, Side};
use crate::exitmap::Fault;

/// Whether the directory whose real path is `dir` is `source`'s, or lies
/// under it.
pub(super) fn inside(source: &str, dir: &str) -> bool {
    let source = source.trim_end_matches('/');
    let dir = dir.trim_end_matches('/');
    dir == source || dir.starts_with(&format!("{source}/"))
}

fn into_itself(source: &str, target: &str) -> Failed {
    Failed::new(Fault::Usage, format!("{source}: a directory cannot move into itself ({target}); nothing was done"))
}

fn there_already(source: &str, target: &str) -> Failed {
    Failed::new(Fault::CantCreate, format!("{target}: there already, so {source} was not moved onto it"))
}

/// The name kept, as `-n` or `-u` asks: the source stays where it is.
fn kept(source: &str, target: &str, log: &Log) -> Done {
    log.info(&clobber::there(target));
    stays(clobber::skipped(source, target, Skip::Exists))
}

/// Rename the directory `source` onto `dest` on the server.
pub(super) async fn rename(link: &Link, source: &str, dest: &str, clobber: Clobber, log: &Log) -> Result<Done, Failed> {
    let (_, name) = transfer::split_remote(source.trim_end_matches('/'));
    match &link.road {
        Road::Sftp(sftp) => {
            let target = transfer::remote_target(sftp, dest, name, false).await?;
            let (dir, _) = transfer::split_remote(&target);
            let real_dir = sftp.realpath(if dir.is_empty() { "." } else { dir }).await.ok();
            if let (Ok(real), Some(real_dir)) = (sftp.realpath(source).await, real_dir) {
                if inside(&real, &real_dir) {
                    return Err(into_itself(source, &target));
                }
            }
            if sftp.lstat(&target).await.is_ok() {
                return match clobber.mode {
                    Mode::Replace => Err(there_already(source, &target)),
                    Mode::Keep | Mode::Update => Ok(kept(source, &target, log)),
                };
            }
            log.verbose(&format!("{source}: a rename of the directory to {target} on the server"));
            sftp.rename(source, &target).await.map_err(|e| {
                let mut failed = transfer::from_sftp(e, Side::Destination);
                failed.message = format!("{source}: the server did not rename it to {target}: {}", failed.message);
                failed
            })?;
            Ok(renamed(source, &target, 0, false))
        }
        Road::Exec(far) => {
            let handle = link.handle();
            let target = far.target(handle, dest, name, false).await?;
            if far.same_file(handle, source, &target).await? {
                return Err(one_file(source, &target));
            }
            if inside(source, &target) {
                return Err(into_itself(source, &target));
            }
            if far.kind(handle, &target).await? != Kind::Missing {
                return match clobber.mode {
                    Mode::Replace => Err(there_already(source, &target)),
                    Mode::Keep | Mode::Update => Ok(kept(source, &target, log)),
                };
            }
            log.verbose(&format!("{source}: a rename of the directory to {target} on the server, by mv"));
            // The name is free: the rename keeps nothing, and places as with
            // no flag.
            let (stamp, keep, plain) = (Stamp::default(), Keep::default(), Clobber::default());
            far.rename(handle, source, &target, &stamp, keep, plain, false, log).await?;
            Ok(renamed(source, &target, 0, false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_never_moves_into_itself() {
        for (source, dir, within) in [
            ("/srv/m/d", "/srv/m/d", true),
            ("/srv/m/d", "/srv/m/d/sub", true),
            ("/srv/m/d/", "/srv/m/d/sub/", true),
            ("/srv/m/d", "/srv/m", false),
            ("/srv/m/d", "/srv/m/d2", false),
            ("/srv/m/d", "/srv/m/dd/x", false),
        ] {
            assert_eq!(inside(source, dir), within, "{source} {dir}");
        }
    }
}
