//! The copy of a directory over one connection (T-143): the walk of
//! `tree.rs`, then each directory made, each file copied as one copy goes
//! (`cp -r`: `session::attempts`, with its continuation after a break;
//! `sftp`'s `get -r` and `put -r`: over the batch's session, T-298; see
//! `tree_conn.rs`), each link made, and each directory's mode, and what `-p`
//! and `--owner` keep, set after its files. Up, two names of one local file
//! arrive as one file with two names (T-146). A device, a FIFO or a socket
//! is not copied, said once, and no failure, as OpenSSH's scp and sftp skip
//! one (T-476); each other item that cannot be copied is said once, the walk
//! goes on, and the exit is then not zero. `--dry-run` says each action and
//! changes nothing. The files wait, then go K at once (`--parallel K`, else
//! the default of T-474), before each directory's mode is set (T-297). The
//! steps on one name each are in `tree_items.rs`. `--no-clobber`, `--update`
//! and `--backup` (T-473, `clobber.rs`) take each file, link and dry run.
//! Each path that the excludes left out of the source is named at `-v` with
//! its pattern, and counted for the summary (T-475); a dry run of `podssh
//! run` plans only what its copy would change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::sftp::{FileAttributes, Sftp};
use podssh_ssh::Log;

use super::clobber::{self, Skip};
use super::dry::{self, Planned};
use super::gauge;
use super::link::{Link, Road};
use super::meta;
use super::mirror::{refused_root, Pending};
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::session::shown;
use super::transfer::{self, Failed, Side};
use super::tree::{self, Item, Special, Tree};
use super::tree_conn::{flush, Conn, Linked, Waiting};
use super::tree_items::{far_dir, far_link, remove_local, same_far, second_name};
use super::Outcome;
use crate::exitmap::Fault;

pub(super) fn remote_join(root: &str, rel: &str) -> String {
    match (root, rel) {
        (_, "") => root.to_string(),
        ("", _) => rel.to_string(),
        _ => format!("{}/{rel}", root.trim_end_matches('/')),
    }
}

pub(super) fn local_join(root: &Path, rel: &str) -> PathBuf {
    rel.split('/').filter(|c| !c.is_empty()).fold(root.to_path_buf(), |path, c| path.join(c))
}

/// The SFTP session of the connection, while it lasts.
pub(super) fn sftp_of(link: &Option<Link>) -> Option<&Sftp> {
    match link.as_ref().map(|l| &l.road) {
        Some(Road::Sftp(sftp)) => Some(sftp),
        _ => None,
    }
}

/// Whether `source` is a directory: here, or on the server over `sftp`.
pub async fn is_dir(sftp: Option<&Sftp>, source: &Operand, tree: &Tree) -> bool {
    match source {
        Operand::Local(path) => std::fs::metadata(path).is_ok_and(|m| m.is_dir()),
        Operand::Remote(remote) => match sftp {
            Some(sftp) if tree.follow => sftp.stat(&remote.path).await.is_ok_and(|a| a.is_dir()),
            Some(sftp) => sftp.lstat(&remote.path).await.is_ok_and(|a| a.is_dir()),
            None => false,
        },
    }
}

/// Record a failure of the tree, and say it at once: each one is reported
/// once, and the first sets the exit code.
pub(super) fn failed(outcome: &mut Outcome, log: &Log, name: String, failed: Failed) {
    outcome.fail(log, name, failed);
}

/// A device, a FIFO or a socket of the tree, `from`: not copied, and no
/// failure (T-476). One line at the default level, and with `--jsonl` a
/// `skipped` object; a dry run says `skip`.
pub(super) fn skipped(outcome: &mut Outcome, log: &Log, from: String, kind: Special, dry_run: bool) {
    if dry_run {
        outcome.planned.push(Planned::skip(from, kind.noun()));
        return;
    }
    log.info(&format!("{from}: not copied: {}", kind.noun()));
    outcome.skipped.push((from, kind.noun()));
}

/// A link of the tree whose name the run left as it was (T-473): said once,
/// and a skip.
pub(super) fn kept(outcome: &mut Outcome, log: &Log, from: String, target: &str, skip: Skip) {
    log.info(&clobber::there(target));
    outcome.skipped.push((from, skip.why()));
}

/// The files of a tree once walked, into the run's count, which its
/// progress line shows (T-472); a dry run copies none.
pub(super) fn count_files(items: &[Item], tree: &Tree) {
    if !tree.dry_run {
        gauge::more_files(items.iter().filter(|item| matches!(item, Item::File { .. })).count());
    }
}

/// The paths of the source that the excludes left out (T-475): each said
/// at `-v` with the pattern that left it out, shown as `shown` gives its
/// path, and counted for the summary, so that an exclude does not read as a
/// file that the copy lost.
pub(super) fn left_out(outcome: &mut Outcome, log: &Log, tree: &Tree, left: &[String], shown: impl Fn(&str) -> String) {
    for rel in left {
        let by = tree.excluded_by(rel).unwrap_or("an exclude");
        log.verbose(&format!("{}: left out by {by}", shown(rel)));
    }
    outcome.left_out += left.len();
}

/// Copy the directory `source` to `dest` over `conn`: up or down.
#[allow(clippy::too_many_arguments)]
pub async fn copy(
    conn: &mut Conn<'_>,
    source: &Operand,
    dest: &Operand,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    let name = shown(source);
    // No server to copy a directory with: 69, as for a server with neither
    // SFTP nor the tools of a copy by exec (T-936).
    if conn.sftp().is_none() {
        let why = format!("{name}: a directory goes over SFTP, and this server has none");
        return failed(outcome, log, name, Failed::new(Fault::RelayUnreachable, why));
    }
    match (source, dest) {
        (Operand::Local(src), Operand::Remote(dst)) => {
            up(conn, src, dst, many, tree, log, shape, moving, outcome).await
        }
        (Operand::Remote(src), Operand::Local(dst)) => {
            super::tree_down::down(conn, src, dst, many, tree, log, shape, moving, outcome).await
        }
        _ => {
            let why = format!("{name}: a directory goes up or down, not from one server to another");
            failed(outcome, log, name, Failed::new(Fault::Usage, why));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn up(
    conn: &mut Conn<'_>,
    src: &str,
    dst: &Remote,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    // `DIR/.` copies what DIR holds into the destination, as GNU cp -r and
    // rsync read it (T-937); `.` has no name of its own either.
    let contents = src.ends_with("/.") || (cfg!(windows) && src.ends_with("\\."));
    let leaf = match contents {
        true => String::new(),
        false => Path::new(src).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
    };
    let Some(sftp) = conn.sftp() else { return };
    // `podssh run` copies onto its directory, also the second time.
    let is_dir = !tree.onto && sftp.stat(&dst.path).await.is_ok_and(|a| a.is_dir());
    let into = !tree.onto && (many || dst.path.is_empty() || dst.path.ends_with('/') || is_dir);
    let root = if into { remote_join(&dst.path, &leaf) } else { dst.path.clone() };
    // A root that is there and is no directory takes no tree: said once,
    // and nothing else is tried (T-935).
    if !tree.onto && !root.is_empty() && sftp.stat(&root).await.is_ok_and(|a| !a.is_dir()) {
        let why = format!("{root}: not a directory, so {src} cannot be copied into it");
        return failed(outcome, log, root.clone(), Failed::new(Fault::CantCreate, why));
    }
    if tree.delete {
        let real = sftp.realpath(if root.is_empty() { "." } else { &root }).await.unwrap_or_else(|_| root.clone());
        let home = sftp.realpath(".").await.ok();
        if let Some(why) = refused_root(&real, home.as_deref()).or_else(|| refused_root(&root, None)) {
            return failed(outcome, log, root, Failed::new(Fault::Usage, why));
        }
    }
    let (items, left) = tree::walk_local(Path::new(src), tree);
    left_out(outcome, log, tree, &left, |rel| local_join(Path::new(src), rel).display().to_string());
    count_files(&items, tree);
    let mut dirs = Vec::new();
    let mut clean = true;
    // The far name, the size and the digest of each file copied that has
    // other names here, by its device and inode (T-146).
    let mut linked = Linked::new();
    // The files wait, then go K at once (T-297, T-474).
    let (batching, mut batch) = (conn.batches(shape), Waiting::new());
    for item in &items {
        match item {
            Item::Dir { rel, stamp } => {
                let target = remote_join(&root, rel);
                if tree.dry_run {
                    // A plan says only what would change: a directory that
                    // is there is no action (T-934).
                    if !far_dir(conn.sftp(), &target).await {
                        let from = local_join(Path::new(src), rel).display().to_string();
                        outcome.planned.push(Planned::step("mkdir", from, target));
                    }
                    continue;
                }
                let Some(sftp) = conn.sftp() else { return };
                let made = match sftp.lstat(&target).await {
                    Ok(attrs) if attrs.is_dir() => Ok(()),
                    _ => sftp.mkdir(&target, FileAttributes::default()).await,
                };
                if let Err(e) = made {
                    clean = false;
                    failed(outcome, log, target.clone(), transfer::from_sftp(e, Side::Destination));
                    continue;
                }
                dirs.push((target, *stamp));
            }
            Item::File { rel } => {
                let from = local_join(Path::new(src), rel).display().to_string();
                let target = remote_join(&root, rel);
                // The look only reads, so a dry run makes it too (T-475).
                if tree.changed_only && same_far(conn.sftp(), &from, &target).await {
                    outcome.unchanged += 1;
                    if !tree.dry_run {
                        gauge::passed();
                    }
                    continue;
                }
                let id = meta::inode(Path::new(&from));
                // Another name of a file that waits: the files that wait go
                // first, so that this name links to its copy.
                let waits = id.is_some() && batch.iter().any(|(_, _, other)| *other == id);
                if waits && !flush(conn, &mut batch, &mut linked, log, shape, outcome, &mut clean).await {
                    return;
                }
                if let Some((first, bytes, sum)) = id.and_then(|id| linked.get(&id)).cloned() {
                    if tree.dry_run {
                        outcome.planned.push(Planned::linked("hardlink", from, target, first));
                        continue;
                    }
                    let Some(sftp) = conn.sftp() else { return };
                    match second_name(sftp, &from, (first.as_str(), bytes, sum), &target, shape.clobber, log).await {
                        Ok(Some(done)) => {
                            gauge::passed();
                            outcome.add(done);
                            continue;
                        }
                        // No hardlink@openssh.com: a copy.
                        Ok(None) => {}
                        Err(f) => {
                            clean = false;
                            failed(outcome, log, from, f);
                            continue;
                        }
                    }
                }
                if tree.dry_run {
                    if let Some(id) = id {
                        linked.entry(id).or_insert((target.clone(), 0, None));
                    }
                    outcome.planned.extend(clobber::dry_up(conn.sftp(), from, target, shape.clobber).await);
                    continue;
                }
                let to = Operand::Remote(Remote { path: target, ..dst.clone() });
                if batching {
                    batch.push((Operand::Local(from), to, id));
                    continue;
                }
                match conn.file(&Operand::Local(from.clone()), &to, log, shape).await {
                    Ok(done) => {
                        // A file left out has no copy for its other names (T-473).
                        if let (Some(id), None) = (id, done.skipped) {
                            linked.entry(id).or_insert((done.destination.clone(), done.bytes, done.sum));
                        }
                        outcome.add(done)
                    }
                    Err(f) => {
                        clean = false;
                        failed(outcome, log, from, f);
                        if conn.gone() {
                            return;
                        }
                    }
                }
            }
            Item::Link { rel, target: names } => {
                let target = remote_join(&root, rel);
                if tree.dry_run {
                    let there = dry::far_there(conn.sftp(), &target, names).await;
                    let from = local_join(Path::new(src), rel).display().to_string();
                    outcome.planned.extend(dry::link_plan(from, target, names.clone(), there, shape.clobber));
                    continue;
                }
                let Some(sftp) = conn.sftp() else { return };
                match far_link(sftp, &target, names, shape.clobber).await {
                    Ok(None) => {}
                    Ok(Some(skip)) => {
                        kept(outcome, log, local_join(Path::new(src), rel).display().to_string(), &target, skip)
                    }
                    Err(e) => {
                        clean = false;
                        failed(outcome, log, target, transfer::from_sftp(e, Side::Destination));
                    }
                }
            }
            Item::Special { rel, kind } => {
                let from = local_join(Path::new(src), rel).display().to_string();
                skipped(outcome, log, from, *kind, tree.dry_run);
            }
            Item::Skip { rel, why } => {
                let from = local_join(Path::new(src), rel).display().to_string();
                if tree.dry_run {
                    outcome.planned.push(Planned::skip(from, why.clone()));
                    continue;
                }
                clean = false;
                failed(outcome, log, from.clone(), Failed::new(Fault::NoInput, format!("{from}: not copied: {why}")));
            }
        }
    }
    if !flush(conn, &mut batch, &mut linked, log, shape, outcome, &mut clean).await {
        return;
    }
    // Each directory's mode, and what -p and --owner keep, after its files,
    // the deepest first; one that the server refuses is said.
    if let Some(sftp) = conn.sftp() {
        for (dir, stamp) in dirs.iter().rev() {
            if let Err(f) = meta::set_far(sftp, dir, stamp, shape.keep, log).await {
                log.info(&f.message);
            }
        }
    }
    // --delete: what the target has and the source lacks; it goes at the end
    // of the run, once each copy of it succeeded (T-144).
    if tree.delete {
        if let Some(sftp) = conn.sftp() {
            let (mut target, _) = tree::walk_far(sftp, &root, &Tree { follow: false, ..tree.clone() }, false).await;
            clobber::protect(&mut target, shape.clobber);
            for item in tree::to_delete(&items, &target) {
                let path = remote_join(&root, tree::rel_of(&item));
                if tree.dry_run {
                    outcome.planned.push(Planned::delete(path));
                } else {
                    outcome.pending.push(Pending { far: true, dir: matches!(item, Item::Dir { .. }), path });
                }
            }
        }
    }
    // mv -r: the source goes once each item of it is copied; what the run
    // left out stays (T-473).
    // mv -r: each path that the move removed, for the record (T-925).
    if moving && clean && !tree.dry_run {
        let gone = remove_local(src, &items, &outcome.left(), log);
        outcome.removed_in_tree(gone);
    }
}
