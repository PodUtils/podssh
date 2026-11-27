//! The user services of `--install` and `--uninstall` (T-121, T-393, T-820),
//! delegated to `pod-unit`: a user unit of systemd (`systemctl --user`), a
//! LaunchAgent (`launchctl` in `gui/UID`), two lines of the crontab, or a
//! task of the Windows Task Scheduler. podssh builds the host's [`Places`],
//! keeps the LaunchAgent's private log file, cleans up any earlier install
//! of another way, and adds its user-facing notes (linger, start-now line).

use std::io::Write;
use std::path::{Path, PathBuf};

use pod_unit::install::{install as unit_install, probe, remove as unit_remove};
use pod_unit::{Form, Host, Places, Removed, System};

use super::{text, Kind, Spec, PROGRAM_LIMIT};
use crate::exitmap::sysexits::EX_UNAVAILABLE;

/// The forms of a user service on this system, in probe order.
#[cfg(unix)]
const USER_FORMS: &[Form] = &[Form::Systemd, Form::Launchd, Form::Cron];
#[cfg(windows)]
const USER_FORMS: &[Form] = &[Form::Task];
#[cfg(not(any(unix, windows)))]
const USER_FORMS: &[Form] = &[];

/// The host's user-service places, with flags for directories or names that
/// the environment did not supply so no form writes into a relative path.
struct UserPlaces {
    places: Places,
    has_systemd_dir: bool,
    has_launchd_dir: bool,
    has_windows_user: bool,
}

impl UserPlaces {
    fn of_host(scratch: PathBuf) -> UserPlaces {
        #[cfg(unix)]
        {
            let systemd_dir = unit_dir();
            let launchd_dir = agents_dir();
            // SAFETY: getuid has no preconditions and cannot fail.
            let uid = unsafe { libc::getuid() };
            UserPlaces {
                has_systemd_dir: systemd_dir.is_some(),
                has_launchd_dir: launchd_dir.is_some(),
                has_windows_user: false,
                places: Places {
                    systemd_user: systemd_dir.unwrap_or_default(),
                    launch_agents: launchd_dir.unwrap_or_default(),
                    scratch,
                    uid,
                    windows_user: String::new(),
                },
            }
        }
        #[cfg(windows)]
        {
            let user = windows_user();
            UserPlaces {
                has_systemd_dir: false,
                has_launchd_dir: false,
                has_windows_user: user.is_some(),
                places: Places {
                    systemd_user: PathBuf::new(),
                    launch_agents: PathBuf::new(),
                    scratch,
                    uid: 0,
                    windows_user: user.unwrap_or_default(),
                },
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            UserPlaces {
                has_systemd_dir: false,
                has_launchd_dir: false,
                has_windows_user: false,
                places: Places {
                    systemd_user: PathBuf::new(),
                    launch_agents: PathBuf::new(),
                    scratch,
                    uid: 0,
                    windows_user: String::new(),
                },
            }
        }
    }

    fn ready(&self, form: Form) -> Result<(), &'static str> {
        match form {
            Form::Systemd if !self.has_systemd_dir => Err("no HOME, for the directory of user units"),
            Form::Launchd if !self.has_launchd_dir => Err("no HOME, for ~/Library/LaunchAgents"),
            Form::Task if !self.has_windows_user => Err("USERNAME is not set, for the logon trigger"),
            _ => Ok(()),
        }
    }
}

/// Where the user's systemd units live: `$XDG_CONFIG_HOME/systemd/user`,
/// else `$HOME/.config/systemd/user`.
#[cfg(unix)]
fn unit_dir() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").filter(|h| !h.is_empty()).map(|home| Path::new(&home).join(".config")))?;
    Some(config.join("systemd").join("user"))
}

/// `~/Library/LaunchAgents`.
#[cfg(unix)]
fn agents_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(|home| Path::new(&home).join("Library/LaunchAgents"))
}

/// `DOMAIN\USER`, as the Windows logon trigger names this user.
#[cfg(windows)]
fn windows_user() -> Option<String> {
    let name = std::env::var("USERNAME").ok().filter(|u| !u.is_empty())?;
    Some(match std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty()) {
        Some(domain) => format!("{domain}\\{name}"),
        None => name,
    })
}

/// The first user form available on this host whose directory or user name
/// is known; on Unix, falls back to cron when `HOME` is unset.
fn pick_form(host: &dyn Host, info: &UserPlaces) -> Result<Form, String> {
    let form = probe(host, &info.places).map_err(|failure| failure.chain())?;
    if let Err(missing) = info.ready(form) {
        if cfg!(unix) && form != Form::Cron {
            let cron_ok = match host.run("crontab", &["-l"], None) {
                Ok(ran) => ran.success() || ran.stderr.contains("no crontab"),
                Err(_) => false,
            };
            if cron_ok {
                return Ok(Form::Cron);
            }
        }
        return Err(missing.to_string());
    }
    Ok(form)
}

/// The LaunchAgent log beside the file of variables, created private (0600)
/// before launchd opens it; an older file keeps its contents.
#[cfg(unix)]
fn prepare_log(spec: &Spec) -> Result<PathBuf, crate::relay_settings::Refusal> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = super::env::log_name(spec.kind, &spec.name);
    let path = spec.env_file.parent().map_or_else(|| PathBuf::from(&name), |dir| dir.join(&name));
    std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(&path).map(|_| path.clone()).map_err(|e| {
        crate::relay_settings::Refusal {
            message: format!("the LaunchAgent's log: {}: {}", path.display(), podssh_ws::text::said(&e)),
            code: EX_UNAVAILABLE,
        }
    })
}

/// Whether the user's systemd units run without a login session.
#[cfg(unix)]
fn linger() -> String {
    let user = ["USER", "LOGNAME"].iter().find_map(|n| std::env::var(n).ok().filter(|u| !u.is_empty()));
    match user {
        Some(user) if Path::new("/var/lib/systemd/linger").join(&user).exists() => {
            format!("lingering is on for {user}: the service runs at boot and after logout")
        }
        Some(user) => format!(
            "lingering is off for {user}: the service runs while {user} has a session; loginctl enable-linger \
             {user}, where this host allows it, keeps it running at boot and after logout"
        ),
        None => {
            "a user unit runs while this user has a session, unless lingering is on (loginctl enable-linger)".into()
        }
    }
}

/// podssh's form-specific notes appended after `pod-unit`'s install line.
fn extra_notes(form: Form, spec: &Spec, info: &UserPlaces, log: Option<&Path>) -> Vec<String> {
    match form {
        Form::Systemd => {
            let mut out = vec![
                "it starts again 5 s after each end, with no limit of starts; after 64 or 78, a refused command line \
                 or setting, it stays down until it is fixed and started"
                    .into(),
            ];
            #[cfg(unix)]
            out.push(linger());
            out
        }
        Form::Launchd => {
            let mut out = Vec::new();
            if let Some(log) = log {
                out.push(format!("its lines go to {}", log.display()));
            }
            out.push(
                "it runs while this user is logged in at the screen: after a reboot, from the login on (macOS's \
                 automatic login starts it with no person)"
                    .into(),
            );
            out
        }
        Form::Cron => vec![
            "two lines of the crontab: one at boot, and one each 5 minutes that starts it again when it is not \
             running, where this host's cron runs them"
                .into(),
            format!("it starts within 5 minutes; to start it now: {}", text::login_line(spec)),
        ],
        Form::Task => vec![
            "it starts again a minute after a failure, and each 5 minutes when it is not running, while this user is \
             logged on"
                .into(),
            format!(
                "after a reboot it waits for the logon of {}: a task at boot, before any logon, needs an \
                 administrator (schtasks /Create /SC ONSTART /RU SYSTEM)",
                info.places.windows_user
            ),
        ],
        Form::Service => Vec::new(),
    }
}

/// Remove `unit` from one user `form` when that form's directory/user is
/// available; missing tools or units of another program leave nothing removed.
fn remove_form(unit: &pod_unit::Unit, form: Form, info: &UserPlaces, host: &dyn Host) -> Vec<String> {
    if info.ready(form).is_err() {
        return Vec::new();
    }
    match unit_remove(unit, form, &info.places, host) {
        Ok(Removed::Done(lines)) => lines,
        Ok(Removed::Nothing) | Err(_) => Vec::new(),
    }
}

/// Make the user service by the first way that is there, remove what another
/// way made for it before, and with no way print the login command and exit 69.
pub(crate) fn install(spec: &Spec, notes: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (verb, name) = (spec.kind.verb(), &spec.name);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut unit = match text::pod_unit(spec) {
        Ok(unit) => unit,
        Err(refusal) => return refusal.report(verb, err),
    };
    if let Err(failure) = unit.check() {
        return super::refusal_of(failure).report(verb, err);
    }
    let scratch = spec.env_file.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let info = UserPlaces::of_host(scratch);
    let host = System { limit: PROGRAM_LIMIT };
    let form = match pick_form(&host, &info) {
        Ok(form) => form,
        Err(why) => {
            let _ = writeln!(
                err,
                "podssh {verb}: {name}: no service of this user can be made here ({why}); run this at login:"
            );
            let _ = writeln!(out, "{}", text::login_line(spec));
            for note in notes {
                let _ = writeln!(err, "podssh {verb}: {name}: {note}");
            }
            let removes = spec.kind.uninstall_words(name);
            let _ = writeln!(err, "podssh {verb}: {name}: podssh {removes} removes the file of its variables");
            return EX_UNAVAILABLE;
        }
    };
    #[cfg(unix)]
    let log_path = if form == Form::Launchd {
        match prepare_log(spec) {
            Ok(log) => {
                unit.log = Some(log.clone());
                Some(log)
            }
            Err(refusal) => return refusal.report(verb, err),
        }
    } else {
        None
    };
    #[cfg(not(unix))]
    let log_path: Option<PathBuf> = None;
    let mut lines = match unit_install(&unit, form, &info.places, &host) {
        Ok(lines) => lines,
        Err(failure) => return super::refusal_of(failure).report(verb, err),
    };
    lines.extend(extra_notes(form, spec, &info, log_path.as_deref()));
    let earlier: Vec<String> = USER_FORMS
        .iter()
        .copied()
        .filter(|&other| other != form)
        .flat_map(|other| remove_form(&unit, other, &info, &host))
        .map(|line| format!("an earlier --install of another way: {line}"))
        .collect();
    for line in lines.iter().chain(&earlier).chain(notes) {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
    }
    let _ = writeln!(err, "podssh {verb}: {name}: podssh {} removes it", spec.kind.uninstall_words(name));
    0
}

/// Remove what `--install` wrote for `kind`'s NAME across each user form,
/// plus the files of its variables, lock and log.
pub(crate) fn uninstall(kind: Kind, name: &str, err: &mut dyn Write) -> i32 {
    let verb = kind.verb();
    let unit = text::base_unit(kind, name, Path::new("/usr/bin/podssh"));
    let info = UserPlaces::of_host(PathBuf::new());
    let host = System { limit: PROGRAM_LIMIT };
    let mut removed: Vec<String> =
        USER_FORMS.iter().copied().flat_map(|form| remove_form(&unit, form, &info, &host)).collect();
    if let Some(path) = super::env::remove(kind, name) {
        removed.push(format!("removed the file of its variables, {}", path.display()));
    }
    if removed.is_empty() {
        let _ = writeln!(err, "podssh {verb}: {name}: nothing that --install writes is here");
    }
    for line in removed {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
    }
    0
}
