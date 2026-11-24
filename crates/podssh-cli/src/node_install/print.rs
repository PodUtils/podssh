//! `--print-unit` of `podssh node` and `podssh serve`: the unit of systemd
//! on stdout, and nothing written: no unit, no file of variables, no state
//! directory. A node's are the words of `--install`: a user unit, or with
//! `--system --run-as USER` the hardened system unit. A person reads it, or
//! puts it in place by hand, on any system.

use std::io::Write;
use std::path::PathBuf;

use super::system::{self, Probes};
use super::{prepare, system_text, text, Kind, Spec, Target};
use crate::exitmap::sysexits::EX_CANTCREAT;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;
use crate::serve::ServeArgs;

/// `podssh node NAME ... --print-unit`.
pub(crate) fn node(args: &NodeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let name = args.name.as_deref().unwrap_or_default();
    let printed = target(args.system, args.run_as.as_deref(), name)
        .and_then(|target| prepare(args, &target, true).and_then(|(spec, _)| unit_of(&spec, &target)));
    say(printed, "node", out, err)
}

/// `podssh serve NAME ... --print-unit`: a unit of serve NAME with these
/// flags, which serve does not install itself.
pub(crate) fn serve(args: &ServeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    say(serve_text(args), "serve", out, err)
}

fn say(printed: Result<String, Refusal>, verb: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match printed {
        Ok(unit) => match out.write_all(unit.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => 0,
            // A closed stdout, as `| head` makes, is no failure of the unit.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => 0,
            Err(e) => Refusal { message: format!("stdout: {e}"), code: EX_CANTCREAT }.report(verb, err),
        },
        Err(refusal) => refusal.report(verb, err),
    }
}

/// This user's unit, or the system unit of `--run-as USER`, whose passwd
/// entry is read; nothing else is probed, as nothing is written.
fn target(system: bool, run_as: Option<&str>, name: &str) -> Result<Target, Refusal> {
    match (system, run_as) {
        (true, Some(user)) => Ok(Target::System(system::check(&Probes::host(), user, name, false)?)),
        _ => Ok(Target::User),
    }
}

fn unit_of(spec: &Spec, target: &Target) -> Result<String, Refusal> {
    match target {
        Target::User => Ok(text::unit(spec)),
        Target::System(account) => system_text::unit(spec, account),
    }
}

fn serve_text(args: &ServeArgs) -> Result<String, Refusal> {
    system::flags(false, false, true, args.system, args.run_as.as_deref())?;
    if args.stdio {
        return Err(Refusal::usage(
            "--print-unit with --stdio: a unit runs serve NAME, the node of a pair; --stdio serves one ProxyCommand",
        ));
    }
    if !args.listen.is_empty() {
        return Err(Refusal::usage(
            "--print-unit with --listen: a unit runs serve NAME, the node of a pair, which listens on nothing",
        ));
    }
    let name = args.name.clone().ok_or_else(|| Refusal::usage("--print-unit needs NAME, the label of a pair"))?;
    crate::pairs::check_label(&name)?;
    let target = target(args.system, args.run_as.as_deref(), &name)?;
    let words = serve_words(args, &name)?;
    // serve keeps no file of variables: the unit names none.
    let exe = super::this_binary()?;
    let spec = Spec { kind: Kind::Serve, name, exe, args: words, dir: None, env_file: PathBuf::new() };
    unit_of(&spec, &target)
}

/// serve's words for its unit: NAME and the flags of this run, each file by
/// its absolute path, as a unit does not start in this directory.
pub(super) fn serve_words(args: &ServeArgs, name: &str) -> Result<Vec<String>, Refusal> {
    let absolute = |flag: &str, value: &str| {
        std::path::absolute(value)
            .map(|path| path.display().to_string())
            .map_err(|e| Refusal::config(format!("{flag} {value}: {e}")))
    };
    let mut words = vec!["serve".to_string(), name.to_string()];
    if let Some(file) = &args.host_key {
        words.extend(["--host-key".to_string(), absolute("--host-key", file)?]);
    }
    for key in &args.authorized_key {
        words.extend(["--authorized-key".to_string(), key.clone()]);
    }
    for file in &args.authorized_keys {
        words.extend(["--authorized-keys".to_string(), absolute("--authorized-keys", file)?]);
    }
    if let Some(file) = &args.policy {
        words.extend(["--policy".to_string(), absolute("--policy", file)?]);
    }
    if let Some(file) = &args.motd {
        words.extend(["--motd".to_string(), absolute("--motd", file)?]);
    }
    for pattern in &args.accept_env {
        words.extend(["--accept-env".to_string(), pattern.clone()]);
    }
    for (flag, value) in [("--shell", &args.shell), ("--pty", &args.pty)] {
        if let Some(value) = value {
            words.extend([flag.to_string(), value.clone()]);
        }
    }
    let switches = [
        ("--no-shell", args.no_shell),
        ("--no-forwarding", args.no_forwarding),
        ("--revoke-ends-sessions", args.revoke_ends_sessions),
        ("--share", args.share),
        ("--shell-integration", args.shell_integration),
    ];
    for (flag, on) in switches {
        if on {
            words.push(flag.to_string());
        }
    }
    text::one_line(&words)?;
    Ok(words)
}
