//! The copy of a far directory down to this host (T-143), a file of its own
//! so that `tree_copy.rs`, which has the copy up and the parts that both
//! share, stays short. Its rules are those of `tree_copy.rs`: each directory
//! made, each file copied as one copy goes, each link made, the modes and
//! what `-p` keeps set after the files, a special file skipped, and a dry
//! run that says only what would change (T-934).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::Log;

use super::clobber;
use super::dry::{self, Planned};
use super::meta;
use super::mirror::{refused_root, Pending};
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::transfer::Failed;
use super::tree::{self, Item, Tree};
use super::tree_conn::{flush, Conn, Linked, Waiting};
use super::tree_copy::{count_files, failed, kept, left_out, local_join, remote_join, skipped};
use super::tree_items::{make_link, remove_far};
use super::words::said;
use super::Outcome;
use crate::exitmap::Fault;

#[allow(clippy::too_many_arguments)]
pub(super) async fn down(
    conn: &mut Conn<'_>,
    src: &Remote,
    dst: &str,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    let leaf = src.path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
    // `DIR/.` copies what DIR holds into the destination, as GNU cp -r and
    // rsync read it (T-937).
    let contents = leaf == ".";
    if !contents {
        if let Err(why) = tree::check_name(&leaf, cfg!(windows)) {
            return failed(outcome, log, src.path.clone(), Failed::new(Fault::Usage, format!("{}: {why}", src.path)));
        }
    }
    let into = !contents && (many || Path::new(dst).is_dir());
    let root = if into { Path::new(dst).join(&leaf) } else { PathBuf::from(dst) };
    // A root that is there and is no directory takes no tree: said once,
    // and nothing else is tried (T-935).
    if !tree.onto && std::fs::metadata(&root).is_ok_and(|m| !m.is_dir()) {
        let shown = root.display().to_string();
        let why = format!("{shown}: not a directory, so {} cannot be copied into it", src.path);
        return failed(outcome, log, shown, Failed::new(Fault::CantCreate, why));
    }
    if tree.delete {
        let real = std::fs::canonicalize(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.display().to_string());
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).ok();
        let home = home.and_then(|h| std::fs::canonicalize(h).ok()).map(|p| p.display().to_string());
        let shown_root = root.display().to_string();
        if let Some(why) = refused_root(&real, home.as_deref()).or_else(|| refused_root(&shown_root, None)) {
            return failed(outcome, log, shown_root, Failed::new(Fault::Usage, why));
        }
    }
    let Some(sftp) = conn.sftp() else { return };
    let (items, left) = tree::walk_far(sftp, &src.path, tree, cfg!(windows)).await;
    left_out(outcome, log, tree, &left, |rel| remote_join(&src.path, rel));
    count_files(&items, tree);
    let mut dirs = Vec::new();
    let mut clean = true;
    // The files wait, then go K at once (T-297, T-474).
    let (batching, mut batch) = (conn.batches(shape), Waiting::new());
    for item in &items {
        match item {
            Item::Dir { rel, stamp } => {
                let target = local_join(&root, rel);
                if tree.dry_run {
                    // A directory that is there is no action (T-934).
                    if !target.is_dir() {
                        outcome.planned.push(Planned::step(
                            "mkdir",
                            remote_join(&src.path, rel),
                            target.display().to_string(),
                        ));
                    }
                    continue;
                }
                if let Err(e) = std::fs::create_dir_all(&target) {
                    clean = false;
                    let shown = target.display().to_string();
                    failed(
                        outcome,
                        log,
                        shown.clone(),
                        Failed::new(Fault::CantCreate, format!("{shown}: {}", said(&e))),
                    );
                    continue;
                }
                dirs.push((target, *stamp));
            }
            Item::File { rel } => {
                let from = remote_join(&src.path, rel);
                let target = local_join(&root, rel).display().to_string();
                if tree.dry_run {
                    outcome.planned.extend(clobber::dry_down(conn.sftp(), from, target, shape.clobber).await);
                    continue;
                }
                let source = Operand::Remote(Remote { path: from.clone(), ..src.clone() });
                if batching {
                    batch.push((source, Operand::Local(target), None));
                    continue;
                }
                match conn.file(&source, &Operand::Local(target), log, shape).await {
                    Ok(done) => outcome.add(done),
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
                let target = local_join(&root, rel);
                if tree.dry_run {
                    let there = dry::local_there(&target, names);
                    let (from, to) = (remote_join(&src.path, rel), target.display().to_string());
                    outcome.planned.extend(dry::link_plan(from, to, names.clone(), there, shape.clobber));
                    continue;
                }
                match make_link(&target, names, shape.clobber) {
                    Ok(None) => {}
                    Ok(Some(skip)) => {
                        kept(outcome, log, remote_join(&src.path, rel), &target.display().to_string(), skip)
                    }
                    Err(e) => {
                        clean = false;
                        let shown = target.display().to_string();
                        let why = format!("{shown}: the link to {names} is not made: {}", said(&e));
                        failed(outcome, log, shown, Failed::new(Fault::CantCreate, why));
                    }
                }
            }
            Item::Special { rel, kind } => skipped(outcome, log, remote_join(&src.path, rel), *kind, tree.dry_run),
            Item::Skip { rel, why } => {
                let from = remote_join(&src.path, rel);
                if tree.dry_run {
                    outcome.planned.push(Planned::skip(from, why.clone()));
                    continue;
                }
                clean = false;
                let fault = if why.starts_with("refused") { Fault::SessionFault } else { Fault::NoInput };
                failed(outcome, log, from.clone(), Failed::new(fault, format!("{from}: not copied: {why}")));
            }
        }
    }
    if !flush(conn, &mut batch, &mut Linked::new(), log, shape, outcome, &mut clean).await {
        return;
    }
    for (dir, stamp) in dirs.iter().rev() {
        if let Err(f) = meta::set_local(dir, stamp, shape.keep, log) {
            log.info(&f.message);
        }
    }
    // --delete: what the target has and the source lacks; it goes at the end
    // of the run (T-144).
    if tree.delete && root.is_dir() {
        let (mut target, _) = tree::walk_local(&root, &Tree { follow: false, ..tree.clone() });
        target.retain(|i| !tree::not_copied(i));
        clobber::protect(&mut target, shape.clobber);
        for item in tree::to_delete(&items, &target) {
            let path = local_join(&root, tree::rel_of(&item)).display().to_string();
            if tree.dry_run {
                outcome.planned.push(Planned::delete(path));
            } else {
                outcome.pending.push(Pending { far: false, dir: matches!(item, Item::Dir { .. }), path });
            }
        }
    }
    // mv -r: each path that the move removed, for the record (T-925).
    if moving && clean && !tree.dry_run {
        if let Some(sftp) = conn.sftp() {
            let gone = remove_far(sftp, &src.path, &items, &outcome.left(), log).await;
            outcome.removed_in_tree(gone);
        }
    }
}
