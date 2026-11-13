//! The shell of `podssh serve`, checked at its start (T-222): the same
//! search as each session's (`podssh_ssh::server::shell`), so that a host
//! where no shell runs is a refusal of the start (78), never a login that
//! ends at once with no word. A shell that `--shell` names is strict: no
//! other is tried in its place. `--no-shell` serves no command and no shell,
//! and skips the search.

use std::io::Write;

use podssh_ssh::server::Settings;

use crate::relay_settings::Refusal;

/// Check that a shell runs, and say which one when a candidate before it
/// failed. Silent when the first candidate runs: each start of a
/// ProxyCommand writes to the client's terminal.
pub fn at_start(settings: &Settings, err: &mut dyn Write) -> Result<(), Refusal> {
    if settings.no_shell {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use podssh_ssh::server::{env, shell};
        let base = settings.base();
        let candidates = shell::candidates(settings.shell.as_deref(), env::lookup(&base, "SHELL"));
        match shell::find(&candidates, &env::without_credentials(&base)) {
            Ok(found) => {
                if let Some(line) = found.passed_over() {
                    let _ = writeln!(err, "podssh serve: shell {line}");
                }
                Ok(())
            }
            Err(none) if settings.shell.is_some() => {
                Err(Refusal::config(format!("{none}: --shell names the one shell, and no other is tried")))
            }
            Err(none) => Err(Refusal::config(format!(
                "{none}; give --shell PATH, or --no-shell to serve no command and no shell"
            ))),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::exitmap::sysexits::EX_CONFIG;

    fn settings(shell: Option<&str>, no_shell: bool) -> Settings {
        let base = vec![("PATH".into(), "/usr/bin:/bin".into())];
        Settings { shell: shell.map(Into::into), no_shell, base_env: Some(base), ..Settings::default() }
    }

    #[test]
    fn a_named_shell_that_is_missing_refuses_the_start() {
        let mut err = Vec::new();
        let refusal = at_start(&settings(Some("/nonexistent"), false), &mut err).expect_err("refused");
        assert_eq!(refusal.code, EX_CONFIG, "{}", refusal.message);
        assert!(refusal.message.contains("--shell /nonexistent: no such file"), "{}", refusal.message);
    }

    #[test]
    fn the_host_shell_passes_in_silence_and_no_shell_skips_the_search() {
        let mut err = Vec::new();
        at_start(&settings(None, false), &mut err).expect("a shell of this host runs");
        assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
        at_start(&settings(Some("/nonexistent"), true), &mut err).expect("--no-shell searches nothing");
    }
}
