//! The writes of a system unit (Unix): the file of the variables, the unit,
//! and `systemctl` (`daemon-reload`, `enable`, `restart`), each step bound
//! in time; and their removal. root writes into the state directory with
//! no link followed and no file written over in place: a new private file,
//! given to the user by its descriptor, then renamed into its place.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::system::{check, Account, Probes};
use super::system_text::{state_dir, unit_name, unit_path};
use super::text::UNIT_MARK;
use super::unix::found;
use super::{env, lock, note_left, prepare, run, said, Kind, Spec, Target};
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_NOPERM, EX_UNAVAILABLE};
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// `podssh node NAME --install --system --run-as USER`.
pub(crate) fn install_node(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    let user = args.run_as.as_deref().unwrap_or_default();
    let made = super::label(args, "--install").and_then(|name| {
        let account = check(&Probes::host(), user, &name, true)?;
        let (spec, notes) = prepare(args, &Target::System(account.clone()), false)?;
        Ok((spec, account, notes))
    });
    match made {
        Ok((spec, account, notes)) => install(&spec, &account, notes, err),
        Err(refusal) => refusal.report("node", err),
    }
}

/// Write the unit of `spec` and its file of variables, then enable and
/// start it. The unit's text is made first, so that a refused path writes
/// nothing.
fn install(spec: &Spec, account: &Account, mut notes: Vec<String>, err: &mut dyn Write) -> i32 {
    let (verb, name, user) = (spec.kind.verb(), &spec.name, &account.user);
    let text = match super::system_text::unit(spec, account) {
        Ok(text) => text,
        Err(refusal) => return refusal.report(verb, err),
    };
    let Some(program) = found("systemctl") else {
        return Refusal { message: "no systemctl on PATH".into(), code: EX_UNAVAILABLE }.report(verb, err);
    };
    let (body, left, dropped) = env::body_for_system();
    note_left(left, &mut notes);
    for variable in dropped {
        notes.push(format!("{variable} is a place of this shell's user, not carried: the unit names {user}'s own"));
    }
    if let Err(why) = write_env(&spec.env_file, body.as_bytes(), account) {
        let message = format!("the file of the service's variables, {}: {why}", spec.env_file.display());
        return Refusal { message, code: EX_CANTCREAT }.report(verb, err);
    }
    let path = unit_path(spec.kind, name);
    if let Err(refusal) = write_unit(&path, &text) {
        return refusal.report(verb, err);
    }
    let unit = unit_name(spec.kind, name);
    let steps: [&[&str]; 3] = [&["daemon-reload"], &["enable", &unit], &["restart", &unit]];
    for args in steps {
        if let Err(why) = step(&program, args) {
            // A unit that cannot run is not left behind.
            let _ = std::fs::remove_file(&path);
            let _ = step(&program, &["daemon-reload"]);
            return Refusal { message: format!("the system unit: {why}"), code: EX_UNAVAILABLE }.report(verb, err);
        }
    }
    let lines = [
        format!("a system unit of systemd, {}, enabled and started: it runs as {user}, from boot on", path.display()),
        "it starts again 5 s after each end, with no limit of starts; after 64 or 78, a refused command line or \
         setting, it stays down until it is fixed and started"
            .to_string(),
        format!("its variables are in {}, a private file of {user}'s", spec.env_file.display()),
        "systemd-analyze security scores its hardening; the unit's comments name each line relaxed".to_string(),
    ];
    for line in lines.iter().chain(&notes) {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
    }
    let _ = writeln!(err, "podssh {verb}: {name}: podssh {} --system removes it", spec.kind.uninstall_words(name));
    0
}

/// `systemctl ARGS`, as a step that must pass.
fn step(program: &Path, args: &[&str]) -> Result<(), String> {
    match run(Command::new(program).args(args)) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!("systemctl {}: {}", args.join(" "), said(&output))),
        Err(why) => Err(why),
    }
}

/// The state directory, made the user's, and in it the file `path` with
/// `body`, of mode 0600 and the user's: a new file, never one that is
/// there, renamed over the old one, so that a link that the user put there
/// is replaced and never followed.
fn write_env(path: &Path, body: &[u8], account: &Account) -> Result<(), String> {
    let dir = path.parent().ok_or("no directory")?;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(format!("{} is there and is no directory", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dir).map_err(|e| format!("{}: {}", dir.display(), podssh_ws::text::said(&e)))?;
        }
        Err(e) => return Err(format!("{}: {}", dir.display(), podssh_ws::text::said(&e))),
    }
    // The parent is root's, so the directory checked is the one changed.
    let shown = |e: std::io::Error| format!("{}: {}", dir.display(), podssh_ws::text::said(&e));
    std::os::unix::fs::lchown(dir, Some(account.uid), Some(account.gid)).map_err(shown)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(shown)?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy().into_owned();
    let new = dir.join(format!(".{name}.{}.new", std::process::id()));
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&new)
        .map_err(|e| format!("{}: {}", new.display(), podssh_ws::text::said(&e)))?;
    let written = std::os::unix::fs::fchown(&made, Some(account.uid), Some(account.gid))
        .and_then(|()| (&made).write_all(body))
        .and_then(|()| made.sync_all())
        .and_then(|()| std::fs::rename(&new, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&new);
        return Err(podssh_ws::text::said(&e));
    }
    Ok(())
}

/// Write the unit, of mode 0644 as each unit is; one that podssh did not
/// write is not replaced (73).
fn write_unit(path: &Path, text: &str) -> Result<(), Refusal> {
    let refused = |why: String| Refusal { message: format!("{}: {why}", path.display()), code: EX_CANTCREAT };
    match std::fs::read(path) {
        Ok(old) if !old.starts_with(UNIT_MARK.as_bytes()) => {
            return Err(refused("is there, and podssh did not write it: remove it first".into()))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(refused(podssh_ws::text::said(&e))),
    }
    let mut new = path.as_os_str().to_owned();
    new.push(".podssh-new");
    let new = PathBuf::from(new);
    let written = std::fs::write(&new, text)
        .and_then(|()| std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)))
        .and_then(|()| std::fs::rename(&new, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&new);
        return Err(refused(podssh_ws::text::said(&e)));
    }
    Ok(())
}

/// `podssh node NAME --uninstall --system`: the unit that podssh wrote,
/// stopped and disabled first, and the file of the variables with its lock
/// and their directory. Nothing to remove is no failure.
pub(crate) fn uninstall(kind: Kind, name: &str, probes: &Probes, err: &mut dyn Write) -> i32 {
    let verb = kind.verb();
    if (probes.euid)() != Some(0) {
        let message = "--uninstall --system removes a system unit: run it as root, such as with sudo";
        return Refusal { message: message.into(), code: EX_NOPERM }.report(verb, err);
    }
    let mut removed = Vec::new();
    let (path, unit) = (unit_path(kind, name), unit_name(kind, name));
    if std::fs::read(&path).is_ok_and(|text| text.starts_with(UNIT_MARK.as_bytes())) {
        let program = found("systemctl").ok_or_else(|| "no systemctl on PATH".to_string());
        let stopped = program.and_then(|program| step(&program, &["disable", "--now", &unit]).map(|()| program));
        if std::fs::remove_file(&path).is_ok() {
            let how = match &stopped {
                Ok(program) => {
                    let _ = step(program, &["daemon-reload"]);
                    "stopped and disabled".to_string()
                }
                Err(why) => format!("not stopped: {why}"),
            };
            removed.push(format!("removed the system unit {} ({how})", path.display()));
        }
    }
    let state = state_dir(kind, name);
    let env_name = env::file_name(kind, name);
    for file in [lock::file_name(&env_name), env_name] {
        let at = state.join(file);
        // unlink takes the link itself, never what it names.
        if std::fs::symlink_metadata(&at).is_ok() && std::fs::remove_file(&at).is_ok() {
            removed.push(format!("removed {}", at.display()));
        }
    }
    if std::fs::remove_dir(&state).is_ok() {
        removed.push(format!("removed {}", state.display()));
    }
    if removed.is_empty() {
        let _ = writeln!(err, "podssh {verb}: {name}: nothing that --install --system writes is here");
    }
    for line in removed {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
    }
    0
}
