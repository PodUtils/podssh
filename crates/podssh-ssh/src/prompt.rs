//! Asking the user something: on the controlling terminal, or through
//! `SSH_ASKPASS`, chosen the way OpenSSH chooses (ssh(1), ENVIRONMENT):
//!
//! - `SSH_ASKPASS_REQUIRE=force`: the askpass program, always;
//! - `SSH_ASKPASS_REQUIRE=prefer`: the askpass program when it is allowed
//!   (a `DISPLAY` or `WAYLAND_DISPLAY` is set), else the terminal;
//! - `SSH_ASKPASS_REQUIRE=never`: the terminal only;
//! - unset: the terminal, and the askpass program only when there is no
//!   terminal and it is allowed.
//!
//! When neither works the answer is [`PromptError::NoTerminal`], and the caller
//! turns that into a refusal that names a remedy. Nothing ever blocks waiting
//! for input that cannot arrive.

use std::ffi::OsString;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    /// No controlling terminal, and no askpass program allowed to stand in.
    NoTerminal,
    /// A terminal that nobody watched: no answer within the limit
    /// (`terminal::UNWATCHED_PROMPT`).
    NoAnswer,
    /// The user cancelled: Ctrl-C or Ctrl-D at a prompt.
    Cancelled,
    /// The askpass program ended not 0, which OpenSSH reads as a cancel: how
    /// it ended (`exited 1`), for the line that names the cause (T-501).
    Exited(String),
    /// The askpass program could not be run.
    Failed(String),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptError::NoTerminal => f.write_str(&why_no_one()),
            PromptError::NoAnswer => {
                write!(f, "nobody answered on the terminal within {} s", crate::terminal::UNWATCHED_PROMPT.as_secs())
            }
            PromptError::Cancelled => f.write_str("cancelled"),
            PromptError::Exited(how) => write!(f, "SSH_ASKPASS {how}"),
            PromptError::Failed(why) => write!(f, "SSH_ASKPASS failed: {why}"),
        }
    }
}

/// Ask `prompt`, echoing the answer or not.
pub fn ask(prompt: &str, echo: bool) -> Result<Zeroizing<String>, PromptError> {
    let askpass = std::env::var_os("SSH_ASKPASS").filter(|v| !v.is_empty());
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().to_ascii_lowercase();
    let display = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
    let (allowed, preferred) = match require.as_str() {
        "force" => (askpass.is_some(), true),
        "prefer" => (askpass.is_some() && display, true),
        "never" => (false, false),
        _ => (askpass.is_some() && display, false),
    };
    if let (true, true, Some(program)) = (allowed, preferred, askpass.as_ref()) {
        return run_askpass(program, prompt);
    }
    match crate::terminal::read_line(prompt, echo) {
        Ok(answer) => Ok(answer),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(PromptError::Cancelled),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err(PromptError::NoAnswer),
        Err(_) => match (allowed, askpass.as_ref()) {
            (true, Some(program)) => run_askpass(program, prompt),
            _ => Err(PromptError::NoTerminal),
        },
    }
}

/// Whether [`ask`] asks the program of `SSH_ASKPASS` and never the terminal
/// (`SSH_ASKPASS_REQUIRE=force`): a run with no person at it may still ask
/// (T-042).
pub fn askpass_only() -> bool {
    std::env::var_os("SSH_ASKPASS").is_some_and(|v| !v.is_empty())
        && std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().eq_ignore_ascii_case("force")
}

/// Whether [`ask`] could reach anyone, without asking: used to skip a method
/// rather than start it and fail halfway.
pub fn can_ask() -> bool {
    let askpass = std::env::var_os("SSH_ASKPASS").is_some_and(|v| !v.is_empty());
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().to_ascii_lowercase();
    if askpass && require == "force" {
        return true;
    }
    let display = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
    controlling_terminal_exists() || (askpass && display && require != "never")
}

/// Why [`can_ask`] found no one to ask, in the words of the variables that
/// the user set: an `SSH_ASKPASS` that is set but not allowed is named, as
/// "no SSH_ASKPASS" would send the user looking for the wrong fault.
pub fn why_no_one() -> String {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    let display = var("DISPLAY").is_some() || var("WAYLAND_DISPLAY").is_some();
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().to_ascii_lowercase();
    no_one(var("SSH_ASKPASS").is_some(), display, &require)
}

/// Why a run may not ask: `BatchMode`, else [`why_no_one`]. A caller that
/// found `batch || !can_ask()` names its cause with this.
pub fn why_not_asked(batch: bool) -> String {
    if batch {
        "BatchMode is yes, which forbids each question".into()
    } else {
        why_no_one()
    }
}

/// [`why_no_one`] of the variables given, for its table test.
fn no_one(askpass: bool, display: bool, require: &str) -> String {
    match (askpass, display, require) {
        (false, ..) => "there is no terminal and no SSH_ASKPASS".into(),
        (true, _, "never") => "there is no terminal, and SSH_ASKPASS_REQUIRE=never forbids SSH_ASKPASS".into(),
        (true, false, _) => "there is no terminal, and SSH_ASKPASS is set but neither DISPLAY nor WAYLAND_DISPLAY \
                             is (SSH_ASKPASS_REQUIRE=force uses it anyway)"
            .into(),
        (true, true, _) => "there is no terminal to ask on".into(),
    }
}

#[cfg(unix)]
fn controlling_terminal_exists() -> bool {
    crate::terminal::ctty::open().is_ok()
}

#[cfg(windows)]
fn controlling_terminal_exists() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("CONIN$").is_ok()
}

/// Run the askpass program with the prompt as its argument; its first line of
/// output is the answer.
fn run_askpass(program: &OsString, prompt: &str) -> Result<Zeroizing<String>, PromptError> {
    let mut command = Command::new(program);
    command.arg(prompt).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    // A run in the background has no console: a console program opens no
    // window of its own (T-383).
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, crate::terminal::child_console_flags());
    let output = command.output().map_err(|e| PromptError::Failed(format!("{}: {e}", program.to_string_lossy())))?;
    let stdout = Zeroizing::new(output.stdout);
    if !output.status.success() {
        return Err(PromptError::Exited(ended(output.status)));
    }
    let text = String::from_utf8_lossy(&stdout);
    let first = text.split('\n').next().unwrap_or_default().trim_end_matches('\r');
    Ok(Zeroizing::new(first.to_string()))
}

/// How a program ended that did not exit 0: `exited 1`, or its signal.
fn ended(status: std::process::ExitStatus) -> String {
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    match (status.code(), signal) {
        (Some(code), _) => format!("exited {code}"),
        (None, Some(signal)) => format!("was killed by signal {signal}"),
        (None, None) => "ended with no exit status".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::no_one;

    /// Each way that no one can be asked names the variable at fault: an
    /// SSH_ASKPASS that is set is never called missing.
    #[test]
    fn the_reason_names_the_variable_at_fault() {
        for (askpass, display, require, says) in [
            (false, false, "", "no SSH_ASKPASS"),
            (false, true, "prefer", "no SSH_ASKPASS"),
            (true, false, "", "neither DISPLAY nor WAYLAND_DISPLAY"),
            (true, false, "prefer", "neither DISPLAY nor WAYLAND_DISPLAY"),
            (true, true, "never", "SSH_ASKPASS_REQUIRE=never"),
            (true, false, "never", "SSH_ASKPASS_REQUIRE=never"),
            (true, true, "", "no terminal to ask on"),
        ] {
            let why = no_one(askpass, display, require);
            assert!(why.contains(says), "{askpass} {display} {require:?}: {why}");
            assert_eq!(askpass, !why.contains("no SSH_ASKPASS"), "{why}");
        }
    }
}
