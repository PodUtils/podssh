//! `podssh serve --gateway FILE` on the command line (T-836): the route
//! table read at the start, which refuses a file that others may write,
//! that does not read, or that holds no route (78), with one line that
//! names the file and its line; and the flags of serve's own sessions,
//! which a gateway refuses (64): it runs nothing here, and lets in the keys
//! of its routes alone, so a flag that would rule a local session or add a
//! key would be a promise that nothing keeps.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::server::gateway::Table;

use crate::relay_settings::Refusal;
use crate::serve::ServeArgs;
use crate::serve_keys::Sources;

/// Where the keys come from: the route table of `--gateway`, else the
/// authorized keys as before.
pub fn sources(args: &ServeArgs, default: Option<PathBuf>) -> Result<Sources, Refusal> {
    let Some(path) = args.gateway.as_deref() else {
        return Sources::of(&args.authorized_key, &args.authorized_keys, default);
    };
    if let Some(flag) = refused_with(args) {
        return Err(Refusal::usage(format!(
            "--gateway and {flag}: a gateway runs nothing on this host and lets in the keys of its routes alone"
        )));
    }
    let table = Table::open(Path::new(path)).map_err(|why| Refusal::config(format!("--gateway {why}")))?;
    Ok(Sources::gateway(Arc::new(table)))
}

/// The first flag given that only serve's own sessions use.
fn refused_with(args: &ServeArgs) -> Option<&'static str> {
    let given = [
        ("--authorized-key", !args.authorized_key.is_empty()),
        ("--authorized-keys", !args.authorized_keys.is_empty()),
        ("--shell", args.shell.is_some()),
        ("--pty", args.pty.is_some()),
        ("--motd", args.motd.is_some()),
        ("--shell-integration", args.shell_integration),
        ("--share", args.share),
        ("--keep-lease", args.keep_lease.is_some()),
        ("--totp", args.totp.is_some()),
        ("--publish-remote", args.publish_remote),
        ("--remote-listen", args.remote_listen),
        ("--revoke-ends-sessions", args.revoke_ends_sessions),
    ];
    given.into_iter().find(|(_, set)| *set).map(|(flag, _)| flag)
}

// Unix's, as serve is: the modes are Unix's.
#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::exitmap::sysexits::{EX_CONFIG, EX_USAGE};

    /// A scratch directory, removed when the test ends, also on a failure.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("podssh-serve-gateway-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn key_line() -> String {
        let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "").unwrap();
        key.public_key().to_openssh().unwrap()
    }

    /// `text` at `name` in `dir`, of `mode`.
    fn write(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Each refusal at the start, by its code and its words: a flag of a
    /// local session (64); a table that is missing, open to others' writes,
    /// broken, empty, or whose CA key others may read (78). A good table
    /// gives the gateway's sources, which read no authorized key.
    #[test]
    fn a_table_is_refused_at_the_start_with_its_code_and_one_true_line() {
        let s = scratch();
        let ca = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "").unwrap();
        let ca_text = ca.to_openssh(podssh_ssh::russh::keys::ssh_key::LineEnding::LF).unwrap();
        write(&s.0, "ca", &ca_text, 0o600);
        write(&s.0, "open_ca", &ca_text, 0o644);
        let route = |ca: &str| {
            format!(
                "route alice\nupstream 127.0.0.1:22\nhost-key {}\nprincipal alice\nca-key {ca}\nkey {}\n",
                key_line(),
                key_line()
            )
        };
        let good = write(&s.0, "good", &route("ca"), 0o644);
        let cases: Vec<(&str, ServeArgs, i32, &str)> = vec![
            (
                "a key flag",
                args(&good, |a| a.authorized_key = vec![key_line()]),
                EX_USAGE,
                "--gateway and --authorized-key",
            ),
            ("a shell", args(&good, |a| a.shell = Some("/bin/sh".into())), EX_USAGE, "--gateway and --shell"),
            ("a second factor", args(&good, |a| a.totp = Some("t".into())), EX_USAGE, "--gateway and --totp"),
            ("a share", args(&good, |a| a.share = true), EX_USAGE, "--gateway and --share"),
            ("no file", args(&s.0.join("none"), |_| ()), EX_CONFIG, "none: no such file"),
            ("others may write", args(&write(&s.0, "open", &route("ca"), 0o666), |_| ()), EX_CONFIG, "open"),
            ("a broken line", args(&write(&s.0, "broken", "route a\nbogus x\n", 0o644), |_| ()), EX_CONFIG, "line 2"),
            ("no route", args(&write(&s.0, "empty", "# none\n", 0o644), |_| ()), EX_CONFIG, "holds no route"),
            ("an open CA", args(&write(&s.0, "open_ca_route", &route("open_ca"), 0o644), |_| ()), EX_CONFIG, "ca-key"),
        ];
        for (what, given, code, words) in cases {
            let refusal = sources(&given, None).expect_err(what);
            assert_eq!(refusal.code, code, "{what}: {}", refusal.message);
            assert!(refusal.message.contains(words), "{what}: {}", refusal.message);
            assert!(!refusal.message.contains('\n'), "{what}: one line");
        }
        let sources = sources(&args(&good, |_| ()), None).expect("a good table");
        assert_eq!(sources.table().map(|t| t.now().len()), Some(1));
        let mut said = Vec::new();
        assert!(sources.read(&mut said).expect("no key file is read").is_empty());
    }

    fn args(table: &Path, change: impl FnOnce(&mut ServeArgs)) -> ServeArgs {
        let mut args = ServeArgs { stdio: true, gateway: Some(table.display().to_string()), ..ServeArgs::default() };
        change(&mut args);
        args
    }
}
