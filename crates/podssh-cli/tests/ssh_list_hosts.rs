//! `podssh ssh --list-hosts` against the binary (T-832): a JSON array on
//! stdout, one record for each literal `Host` alias, a pattern left out and
//! an `Include` followed, exit 0; a file that cannot be read exits 78 with
//! nothing on stdout; a destination exits 64. Which faults stop the list
//! and which are one alias's `error` is one table (T-867). Nothing connects: the relay
//! and the proxies of the host are taken away, and a run that waits fails.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A scratch home of one test, private as a user's home is, removed when
/// dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-list-hosts-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        podssh_relay::cache::private_dir(&dir).expect("a scratch home");
        std::fs::create_dir_all(dir.join(".ssh").join("conf.d")).expect("a scratch home");
        Home(dir)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("a config file");
        path
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `podssh ssh ARGS` with this home and nothing of the host's own: no relay,
/// no proxy, no settings file, a fixed login name.
fn podssh(home: &Path, args: &[&str]) -> Output {
    podssh_with(home, args, &[])
}

/// As [`podssh`], with the variables of `vars` set after the others go.
fn podssh_with(home: &Path, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("ssh").args(args).env("HOME", home).env("USERPROFILE", home);
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_USER", "lu");
    for name in ["PODSSH_SSH_CONFIG", "PODSSH_RELAY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(name);
    }
    cmd.envs(vars.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh");
    // The run to its end within 30 s: a run that waits must fail the test.
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("a wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("no end within 30 s: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("the output")
}

#[test]
fn the_list_is_one_record_for_each_alias_patterns_left_out_includes_followed() {
    let h = Home::new("list");
    h.file(".ssh/conf.d/extra", "Host extra1 extra?\n    HostName extra.internal\n");
    let config = h.file(
        "config",
        "Include conf.d/*\nHost web1 web2\n    HostName %h.example.org\n    User admin\n    Port 2222\n\
         Host *.example.org !bad.example.org\nHost db\n    HostName db.internal\n    ProxyJump web1\n\
         Host -bad\n",
    );
    let config = config.display().to_string();
    let out = podssh(&h.0, &["-F", &config, "--list-hosts"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{said}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON on stdout");
    let rows = value.as_array().expect("an array");
    let aliases: Vec<&str> = rows.iter().map(|r| r["alias"].as_str().expect("an alias")).collect();
    assert_eq!(aliases, ["extra1", "web1", "web2", "db", "-bad"]);
    // (alias, host, port, user, jump) of each row that resolves.
    #[rustfmt::skip]
    let table = [
        ("extra1", "extra.internal", 22, "lu", None),
        ("web1", "web1.example.org", 2222, "admin", None),
        ("web2", "web2.example.org", 2222, "admin", None),
        ("db", "db.internal", 22, "lu", Some("web1")),
    ];
    for (row, (alias, host, port, user, jump)) in rows.iter().zip(table) {
        assert_eq!(row["error"], serde_json::Value::Null, "{alias}: {row}");
        let have = (row["host"].as_str(), row["port"].as_u64(), row["user"].as_str());
        assert_eq!(have, (Some(host), Some(port), Some(user)), "{alias}");
        assert_eq!(row["proxy_jump"].as_str(), jump, "{alias}");
        let ids = row["identity_files"].as_array().expect("the identity files");
        assert!(!ids.is_empty(), "{alias}: OpenSSH's defaults when none is given");
    }
    let bad = &rows[4];
    assert!(bad["error"].as_str().is_some_and(|e| e.contains("cannot start with '-'")), "{bad}");
    assert_eq!(bad["host"], serde_json::Value::Null);
    // Nothing secret is in the list: no key's contents, no passphrase field.
    let text = String::from_utf8_lossy(&out.stdout);
    for word in ["PRIVATE KEY", "passphrase", "password"] {
        assert!(!text.contains(word), "{word} in {text}");
    }
}

#[test]
fn a_file_that_cannot_be_read_exits_78_and_a_destination_64() {
    let h = Home::new("unread");
    let dir = h.0.join(".ssh").display().to_string();
    let out = podssh(&h.0, &["-F", &dir, "--list-hosts"]);
    assert_eq!(out.status.code(), Some(78), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "no list on stdout");
    assert!(String::from_utf8_lossy(&out.stderr).contains(&dir));
    let missing = h.0.join("nothing-here").display().to_string();
    let out = podssh(&h.0, &["-F", &missing, "--list-hosts"]);
    assert_eq!(out.status.code(), Some(78), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "no list on stdout");
    let out = podssh(&h.0, &["--list-hosts", "web1"]);
    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--list-hosts"));
}

/// An `Include` of a file that others may change is refused as a run
/// refuses it: the list is no list (78).
#[cfg(unix)]
#[test]
fn an_included_file_that_others_may_change_exits_78() {
    use std::os::unix::fs::PermissionsExt;
    let h = Home::new("perm");
    let open = h.file(".ssh/conf.d/open", "Host loose\n");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o666)).expect("a mode");
    let config = h.file("config", "Include conf.d/*\nHost fine\n").display().to_string();
    let out = podssh(&h.0, &["-F", &config, "--list-hosts"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{said}");
    assert!(said.contains("bad owner or permissions"), "{said}");
    assert!(out.stdout.is_empty(), "no list on stdout");
}

/// How a row of the faults' table ends.
#[derive(Debug, Clone, Copy)]
enum Ends {
    /// 78, nothing on stdout, and stderr holds the words.
    Stops,
    /// 0, and the alias `bad` has `error` with the words; `good` resolves.
    Error,
    /// 0, and `good` resolves to the host of the words, as written.
    Listed,
}

/// One rule (T-867): a fault that each alias meets stops the list (78) -- a
/// file that the list reads, a line that holds for any host, a variable; a
/// fault of one alias's own block is that alias's `error`, and the list goes
/// on (0). The manual's note under --list-hosts lists the same rows. A
/// name is not resolved: `HostName 300.1.1.1` is listed as written. The
/// file of -F is the user's choice, unchecked, as OpenSSH reads it; each
/// file that it includes is checked. `{config}` is the file's path.
#[test]
fn a_fault_that_each_alias_meets_stops_the_list_and_a_block_s_fault_is_its_error() {
    struct Row {
        what: &'static str,
        config: &'static str,
        /// A file under `~/.ssh/conf.d`, mode 0666 where modes exist.
        open: Option<&'static str>,
        /// Mode 0666 on the file of -F itself.
        open_config: bool,
        vars: &'static [(&'static str, &'static str)],
        ends: Ends,
        says: &'static str,
    }
    let row = |what: &'static str, config: &'static str, ends: Ends, says: &'static str| Row {
        what,
        config,
        open: None,
        open_config: false,
        vars: &[],
        ends,
        says,
    };
    // (what, the file of -F, how it ends, the words of the end)
    #[rustfmt::skip]
    let mut table = vec![
        row("a bad port in a block", "Host good\nHost bad\n    Port 99999\n", Ends::Error, "{config}:3"),
        row("no value in a block", "Host good\nHost bad\n    HostName\n", Ends::Error, "missing value"),
        row("a bad port for any host", "Port 99999\nHost good\nHost bad\n", Ends::Stops, "{config}:1"),
        row("a bad port under Host *", "Host good\nHost bad\nHost *\n    Port 99999\n", Ends::Stops, "{config}:4"),
        row("an included file that is missing", "Include /nonexistent-podssh/x\nHost good\n", Ends::Listed, "good"),
        row("an address that no host has", "Host good\n    HostName 300.1.1.1\n", Ends::Listed, "300.1.1.1"),
        Row {
            vars: &[("PODSSH_RELAY", "bad host!")],
            ..row("a bad variable", "Host good\nHost bad\n", Ends::Stops, "PODSSH_RELAY")
        },
    ];
    if cfg!(unix) {
        let top = "Include conf.d/open\nHost good\nHost bad\n";
        let block = "Host good\nHost bad\n    Include conf.d/open\n";
        table.push(Row { open: Some("open"), ..row("an Include for any host, 0666", top, Ends::Stops, "bad owner") });
        table.push(Row { open: Some("open"), ..row("an Include of a block, 0666", block, Ends::Error, "bad owner") });
        let loose = "Host good\n    HostName loose.internal\n";
        table.push(Row { open_config: true, ..row("the file of -F, 0666", loose, Ends::Listed, "loose.internal") });
    }
    for (i, r) in table.iter().enumerate() {
        let h = Home::new(&format!("fault{i}"));
        let config = h.file("config", r.config);
        if let Some(name) = r.open {
            let path = h.file(&format!(".ssh/conf.d/{name}"), "Host loose\n");
            open_to_all(&path);
        }
        if r.open_config {
            open_to_all(&config);
        }
        let config = config.display().to_string();
        let says = r.says.replace("{config}", &config);
        let out = podssh_with(&h.0, &["-F", &config, "--list-hosts"], r.vars);
        let said = String::from_utf8_lossy(&out.stderr);
        if let Ends::Stops = r.ends {
            assert_eq!(out.status.code(), Some(78), "{}: {said}", r.what);
            assert!(out.stdout.is_empty(), "{}: no list on stdout", r.what);
            assert!(said.contains(&says), "{}: {said}", r.what);
            continue;
        }
        assert_eq!(out.status.code(), Some(0), "{}: {said}", r.what);
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON on stdout");
        let rows = value.as_array().expect("an array");
        let of = |alias: &str| rows.iter().find(|row| row["alias"] == alias).cloned();
        let good = of("good").unwrap_or_else(|| panic!("{}: no good in {value}", r.what));
        assert_eq!(good["error"], serde_json::Value::Null, "{}: {good}", r.what);
        match r.ends {
            Ends::Error => {
                let bad = of("bad").unwrap_or_else(|| panic!("{}: no bad in {value}", r.what));
                let error = bad["error"].as_str().unwrap_or_default();
                assert!(error.contains(&says), "{}: {bad}", r.what);
                assert_eq!(bad["host"], serde_json::Value::Null, "{}", r.what);
            }
            _ => assert!(good.to_string().contains(&says), "{}: {good}", r.what),
        }
    }
}

/// Mode 0666: a file that others may change. Nothing where modes do not
/// exist, whose rows are not in the table.
fn open_to_all(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).expect("a mode");
    }
    let _ = path;
}
