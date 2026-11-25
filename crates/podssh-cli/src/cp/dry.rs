//! A dry run (T-143): what each action would be, and nothing changed. Each
//! action names its source and its destination apart, a link the name that
//! it would hold (`target`) and a skip its reason (`reason`), so that the
//! `--jsonl` plan has one meaning for each key. The plan says only what
//! would change: a directory or a link that is there as the copy would make
//! it is no action. A source that is a single file under `-r --dry-run` is
//! planned too, and nothing is written, moved or removed for it.

use std::path::Path;

use podssh_ssh::sftp::Sftp;
use podssh_ssh::Log;
use serde_json::{json, Value};

use super::clobber::{self, Clobber, Mode, Skip};
use super::link::{Link, Road};
use super::operand::Operand;
use super::session::shown;
use super::transfer::{self, Failed, Side};
use super::tree_copy::sftp_of;
use super::words::said;
use super::Outcome;
use crate::exitmap::Fault;

/// One action of a dry run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// `mkdir`, `copy`, `rename`, `link`, `hardlink`, `backup`, `delete` or
    /// `skip`.
    pub action: &'static str,
    /// What the action reads: none for `delete`.
    pub source: Option<String>,
    /// What the action makes or changes: none for `skip`.
    pub destination: Option<String>,
    /// What a `link` or a `hardlink` would name.
    pub target: Option<String>,
    /// Why a `skip` leaves its source.
    pub reason: Option<String>,
}

impl Planned {
    /// An action from `source` to `destination`.
    pub fn step(action: &'static str, source: String, destination: String) -> Planned {
        Planned { action, source: Some(source), destination: Some(destination), target: None, reason: None }
    }

    /// A link at `destination` that names `target`, for `source`.
    pub fn linked(action: &'static str, source: String, destination: String, target: String) -> Planned {
        Planned { target: Some(target), ..Planned::step(action, source, destination) }
    }

    /// `source` left as it is, and why.
    pub fn skip(source: String, reason: impl Into<String>) -> Planned {
        Planned { action: "skip", source: Some(source), destination: None, target: None, reason: Some(reason.into()) }
    }

    /// `path` that `--delete` would remove.
    pub fn delete(path: String) -> Planned {
        Planned { action: "delete", source: None, destination: Some(path), target: None, reason: None }
    }

    /// The line of `cp -r --dry-run` and of `podssh run --dry-run` (T-475).
    pub fn line(&self) -> String {
        let at = |text: &Option<String>| text.clone().unwrap_or_default();
        let (from, to, target, why) = (at(&self.source), at(&self.destination), at(&self.target), at(&self.reason));
        match self.action {
            "mkdir" => format!("mkdir {to}"),
            "delete" => format!("delete {to}"),
            "link" | "hardlink" => format!("{} {to} -> {target}", self.action),
            "skip" => format!("skip {from}: {why}"),
            // copy, rename and backup (T-473): from, then to.
            action => format!("{action} {from} -> {to}"),
        }
    }

    /// The `plan` object of `--jsonl`: `target` and `reason` only where the
    /// action has one.
    pub fn json(&self) -> Value {
        let mut object = json!({
            "event": "plan",
            "action": self.action,
            "source": self.source,
            "destination": self.destination,
        });
        if let Some(target) = &self.target {
            object["target"] = target.as_str().into();
        }
        if let Some(reason) = &self.reason {
            object["reason"] = reason.as_str().into();
        }
        object
    }
}

/// What is at the name of a link of a tree now, as a dry run looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum There {
    Missing,
    /// A link that names what the copy would name: no action.
    Same,
    Dir,
    Other,
}

/// What the far `target` is, for a link that would name `names`.
pub(super) async fn far_there(sftp: Option<&Sftp>, target: &str, names: &str) -> There {
    let Some(sftp) = sftp else { return There::Missing };
    match sftp.lstat(target).await {
        Ok(attrs) if attrs.is_symlink() && sftp.readlink(target).await.is_ok_and(|now| now == names) => There::Same,
        Ok(attrs) if attrs.is_dir() => There::Dir,
        Ok(_) => There::Other,
        Err(_) => There::Missing,
    }
}

/// What the local `at` is, for a link that would name `names`.
pub(super) fn local_there(at: &Path, names: &str) -> There {
    match std::fs::symlink_metadata(at) {
        Ok(meta)
            if meta.file_type().is_symlink() && std::fs::read_link(at).is_ok_and(|now| now == Path::new(names)) =>
        {
            There::Same
        }
        Ok(meta) if meta.is_dir() => There::Dir,
        Ok(_) => There::Other,
        Err(_) => There::Missing,
    }
}

/// The plan of one link of a tree, as `far_link` and `make_link` would act:
/// nothing for a link that is there already, a skip where `-n` or `-u`
/// keeps a name, the backup first under `-b`, then the link.
pub fn link_plan(source: String, dest: String, names: String, there: There, clobber: Clobber) -> Vec<Planned> {
    let link = || Planned::linked("link", source.clone(), dest.clone(), names.clone());
    match there {
        There::Same => Vec::new(),
        There::Missing => vec![link()],
        _ if clobber.mode != Mode::Replace => vec![Planned::skip(source.clone(), Skip::Exists.why())],
        There::Other => match clobber.backup {
            Some(suffix) => vec![Planned::step("backup", dest.clone(), format!("{dest}{suffix}")), link()],
            None => vec![link()],
        },
        There::Dir => vec![link()],
    }
}

/// `-r --dry-run` with a source that is one file (T-924): its plan, as a
/// file of a tree's (`copy`, `skip` or `backup`), into the destination
/// as the copy would place it, and for `mv` the delete of its source.
/// Nothing is written, moved or removed; a
/// source that is missing, or a destination that cannot take it, fails as
/// the copy would.
#[allow(clippy::too_many_arguments)]
pub(super) async fn file(
    link: &Option<Link>,
    source: &Operand,
    dest: &Operand,
    many: bool,
    clobber: Clobber,
    moving: bool,
    log: &Log,
    outcome: &mut Outcome,
) {
    let sftp = sftp_of(link);
    let planned = match (source, dest) {
        (Operand::Local(path), Operand::Remote(to)) => {
            match std::fs::metadata(path) {
                Ok(meta) if meta.is_file() => {}
                Ok(_) => return outcome.fail(log, path.clone(), not_a_file(path)),
                Err(e) => {
                    return outcome.fail(
                        log,
                        path.clone(),
                        Failed::new(Fault::NoInput, format!("{path}: {}", said(&e))),
                    )
                }
            }
            let name = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
            let target = match link.as_ref().map(|l| (&l.road, l)) {
                Some((Road::Sftp(sftp), _)) => transfer::remote_target(sftp, &to.path, name, many).await,
                Some((Road::Exec(far), l)) => far.target(l.handle(), &to.path, name, many).await,
                None => Ok(to.path.clone()),
            };
            match target {
                Ok(target) => clobber::dry_up(sftp, path.clone(), target, clobber).await,
                Err(f) => return outcome.fail(log, path.clone(), f),
            }
        }
        (Operand::Remote(from), Operand::Local(to)) => {
            if let Some(sftp) = sftp {
                match sftp.stat(&from.path).await {
                    Ok(attrs) if attrs.is_regular() => {}
                    Ok(_) => return outcome.fail(log, from.path.clone(), not_a_file(&from.path)),
                    Err(e) => return outcome.fail(log, from.path.clone(), transfer::from_sftp(e, Side::Source)),
                }
            }
            let name = from.path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            match transfer::local_target(to, name, many) {
                Ok(target) => clobber::dry_down(sftp, from.path.clone(), target.display().to_string(), clobber).await,
                Err(f) => return outcome.fail(log, from.path.clone(), f),
            }
        }
        // Within one server, or between two: the copy names its operands.
        _ => vec![Planned::step("copy", shown(source), shown(dest))],
    };
    outcome.planned.extend(planned);
    // `mv` removes its source once the copy is verified.
    if moving {
        outcome.planned.push(Planned::delete(shown(source)));
    }
}

fn not_a_file(path: &str) -> Failed {
    Failed::new(Fault::NoInput, format!("{path}: not a regular file; podssh cp copies files"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One table: each action's line, and its object with the keys that it
    /// has, `target` for a link and `reason` for a skip alone.
    #[test]
    fn each_action_has_its_line_and_its_keys() {
        let s = |t: &str| t.to_string();
        let cases = [
            (
                Planned::step("mkdir", s("src/a"), s("up/a")),
                "mkdir up/a",
                json!({"source": "src/a", "destination": "up/a"}),
            ),
            (Planned::step("copy", s("f"), s("up/f")), "copy f -> up/f", json!({"source": "f", "destination": "up/f"})),
            (
                Planned::step("backup", s("d/f"), s("d/f~")),
                "backup d/f -> d/f~",
                json!({"source": "d/f", "destination": "d/f~"}),
            ),
            (
                Planned::linked("link", s("src/l"), s("up/l"), s("../x")),
                "link up/l -> ../x",
                json!({"source": "src/l", "destination": "up/l", "target": "../x"}),
            ),
            (
                Planned::linked("hardlink", s("src/b"), s("up/b"), s("up/a")),
                "hardlink up/b -> up/a",
                json!({"source": "src/b", "destination": "up/b", "target": "up/a"}),
            ),
            (
                Planned::skip(s("t/a"), "exists"),
                "skip t/a: exists",
                json!({"source": "t/a", "destination": null, "reason": "exists"}),
            ),
            (Planned::delete(s("up/old")), "delete up/old", json!({"source": null, "destination": "up/old"})),
        ];
        for (planned, line, keys) in cases {
            assert_eq!(planned.line(), line);
            let object = planned.json();
            assert_eq!((&object["event"], object["action"].as_str()), (&json!("plan"), Some(planned.action)));
            let want = keys.as_object().unwrap();
            for (key, value) in want {
                assert_eq!(&object[key], value, "{line}: {key}");
            }
            for key in ["target", "reason"] {
                assert_eq!(object.get(key).is_some(), want.contains_key(key), "{line}: {key}");
            }
        }
    }

    #[test]
    fn a_link_is_planned_only_where_it_would_change() {
        let plan = |there, clobber| {
            link_plan("src/l".into(), "up/l".into(), "x".into(), there, clobber)
                .into_iter()
                .map(|p| p.line())
                .collect::<Vec<_>>()
        };
        let keep = Clobber { mode: Mode::Keep, backup: None };
        let backup = Clobber { backup: Some("~"), ..Clobber::default() };
        assert!(plan(There::Same, Clobber::default()).is_empty(), "a link that is there as it would be");
        assert!(plan(There::Same, keep).is_empty());
        assert_eq!(plan(There::Missing, keep), ["link up/l -> x"]);
        assert_eq!(plan(There::Other, keep), ["skip src/l: exists"]);
        assert_eq!(plan(There::Other, Clobber::default()), ["link up/l -> x"]);
        assert_eq!(plan(There::Other, backup), ["backup up/l -> up/l~", "link up/l -> x"]);
        assert_eq!(plan(There::Dir, backup), ["link up/l -> x"], "a directory takes no backup");
    }
}
