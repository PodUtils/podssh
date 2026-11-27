//! The writes of a system unit (Unix, T-709, T-820): the private file of
//! variables owned by the service account (`write_env`), then the unit write,
//! `systemctl` steps (`daemon-reload`, `enable`, `restart`), rollback and
//! removal through `pod_unit::install::{install_system, remove_system}`. root
//! writes into the state directory with no link followed and no file written
//! over in place: a new private file, given to the user by its descriptor,
//! then renamed into its place.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use pod_unit::install::{install_system, remove_system};
use pod_unit::{Form, Host, Removed, System, SystemPlaces};

use super::system::{check, Account, Probes};
use super::system_text::state_dir;
use super::{env, lock, note_left, prepare, Kind, Spec, Target, PROGRAM_LIMIT};
use crate::exitmap::sysexits::EX_CANTCREAT;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// Host adapter forwarding `admin` and `systemd_booted` to [`Probes`] so
/// tests can supply their own probes without root.
struct SystemHost<'a, 'b> {
    inner: System,
    probes: &'a Probes<'b>,
}

impl Host for SystemHost<'_, '_> {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<pod_core::process::Ran, pod_core::Failure> {
        self.inner.run(program, args, input)
    }

    fn admin(&self) -> bool {
        (self.probes.euid)() == Some(0)
    }

    fn systemd_booted(&self) -> bool {
        (self.probes.systemd)()
    }
}

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
/// start it. The unit is rendered first, so that a refused path or secret
/// writes nothing.
fn install(spec: &Spec, account: &Account, mut notes: Vec<String>, err: &mut dyn Write) -> i32 {
    let (verb, name, user) = (spec.kind.verb(), &spec.name, &account.user);
    let unit = match super::system_text::pod_unit(spec, account) {
        Ok(unit) => unit,
        Err(refusal) => return refusal.report(verb, err),
    };
    if let Err(failure) = pod_unit::systemd::render(&unit) {
        return super::refusal_of(failure).report(verb, err);
    }
    let (body, left, dropped) = env::body_for_system();
    note_left(left, &mut notes);
    for variable in dropped {
        notes.push(format!("{variable} is a place of this shell's user, not carried: the unit names {user}'s own"));
    }
    if let Err(why) = write_env(&spec.env_file, body.as_bytes(), account) {
        let message = format!("the file of the service's variables, {}: {why}", spec.env_file.display());
        return Refusal { message, code: EX_CANTCREAT }.report(verb, err);
    }
    let host = System { limit: PROGRAM_LIMIT };
    let mut lines = match install_system(&unit, Form::Systemd, &SystemPlaces::default(), &host) {
        Ok(lines) => lines,
        Err(failure) => return super::refusal_of(failure).report(verb, err),
    };
    lines.extend([
        format!("it runs as {user}, from boot on"),
        "it starts again 5 s after each end, with no limit of starts; after 64 or 78, a refused command line or \
         setting, it stays down until it is fixed and started"
            .to_string(),
        format!("its variables are in {}, a private file of {user}'s", spec.env_file.display()),
        "systemd-analyze security scores its hardening; the unit's comments name each line relaxed".to_string(),
    ]);
    for line in lines.iter().chain(&notes) {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
    }
    let _ = writeln!(err, "podssh {verb}: {name}: podssh {} --system removes it", spec.kind.uninstall_words(name));
    0
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

/// `podssh node NAME --uninstall --system`: the unit that podssh wrote,
/// stopped and disabled first through `pod_unit::install::remove_system`,
/// and the file of the variables with its lock and their directory. Nothing
/// to remove is no failure.
pub(crate) fn uninstall(kind: Kind, name: &str, probes: &Probes, err: &mut dyn Write) -> i32 {
    let verb = kind.verb();
    let unit = super::text::base_unit(kind, name, Path::new("/usr/bin/podssh")).system(None);
    let host = SystemHost { inner: System { limit: PROGRAM_LIMIT }, probes };
    let mut removed = match remove_system(&unit, Form::Systemd, &SystemPlaces::default(), &host) {
        Ok(Removed::Done(lines)) => lines,
        Ok(Removed::Nothing) => Vec::new(),
        Err(failure) => return super::refusal_of(failure).report(verb, err),
    };
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
