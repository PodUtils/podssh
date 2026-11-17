//! The system unit of a named user and `--print-unit` (T-709): the unit's
//! text (its user, its places, each line of its hardening, each relaxed
//! line named, no secret), the checks of a system install with each probe
//! given (no root, no systemd, no passwd entry, no cache), the flags, and a
//! printed unit that writes no file.
// The system unit's tests run on Unix alone; their imports go unused elsewhere.
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]

use std::path::{Path, PathBuf};

use super::env::{without, HOME_BOUND, SECRET};
use super::system::{account_in, check, flags, path_ok, user_name_ok, Account, Probes};
use super::system_text::{env_path, state_dir, unit, unit_path, Needs};
use super::text::UNIT_MARK;
use super::{Kind, Spec};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};

fn alice() -> Account {
    Account {
        user: "alice".into(),
        uid: 1000,
        gid: 1000,
        home: PathBuf::from("/home/alice"),
        shell: Some("/bin/bash".into()),
    }
}

fn node(args: &[&str]) -> Spec {
    let env_file = env_path(Kind::Node, "lab");
    let mut words: Vec<String> = ["node", "lab", "127.0.0.1:22"].iter().map(|s| s.to_string()).collect();
    words.extend(args.iter().map(|s| s.to_string()));
    words.extend(["--env-file".to_string(), env_file.display().to_string()]);
    let exe = PathBuf::from("/usr/local/bin/podssh");
    Spec { kind: Kind::Node, name: "lab".into(), exe, args: words, dir: None, env_file }
}

fn serve(args: &[&str]) -> Spec {
    let mut words: Vec<String> = ["serve", "lab"].iter().map(|s| s.to_string()).collect();
    words.extend(args.iter().map(|s| s.to_string()));
    let exe = PathBuf::from("/usr/local/bin/podssh");
    Spec { kind: Kind::Serve, name: "lab".into(), exe, args: words, dir: None, env_file: PathBuf::new() }
}

/// The lines of `text`'s section `name`.
fn section(text: &str, name: &str) -> Vec<String> {
    let start = text.find(&format!("[{name}]\n")).unwrap_or_else(|| panic!("[{name}]: {text}"));
    let rest = &text[start + name.len() + 3..];
    rest[..rest.find("\n[").unwrap_or(rest.len())].lines().map(str::to_string).collect()
}

const HARDENED: &[&str] = &[
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "ProtectSystem=strict",
    "ProtectHome=tmpfs",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
    "SystemCallFilter=@system-service",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
];

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn a_system_unit_runs_as_its_user_in_its_places_with_each_line_of_the_hardening() {
    let text = unit(&node(&[]), &alice()).expect("a unit");
    assert!(text.starts_with(UNIT_MARK), "{text}");
    assert!(
        text.starts_with(
            "# Written by podssh node lab --install --system --run-as alice; podssh node lab --uninstall --system \
             removes it.\n"
        ),
        "{text}"
    );
    let service = section(&text, "Service");
    for line in [
        "User=alice",
        "Environment=HOME=/home/alice",
        "Environment=XDG_CACHE_HOME=/home/alice/.cache",
        "Environment=XDG_CONFIG_HOME=/home/alice/.config",
        "StateDirectory=podssh-node-lab",
        "StateDirectoryMode=0700",
        "ExecStart=/usr/local/bin/podssh node lab 127.0.0.1:22 --env-file /var/lib/podssh-node-lab/node-lab.env",
        "Restart=always",
        "RestartSec=5",
        "RestartPreventExitStatus=64 78",
        "BindPaths=/home/alice/.cache/podssh",
        "BindReadOnlyPaths=-/home/alice/.config/podssh",
    ]
    .iter()
    .chain(HARDENED)
    {
        assert!(service.iter().any(|l| l == line), "{line}: {text}");
    }
    assert!(section(&text, "Install").iter().any(|l| l == "WantedBy=multi-user.target"), "{text}");
    assert!(section(&text, "Unit").iter().any(|l| l == "StartLimitIntervalSec=0"), "{text}");
    assert!(!text.contains("Relaxed"), "a plain node relaxes nothing: {text}");
    // Each line that is not blank is a comment, a section or a key.
    for line in text.lines().filter(|l| !l.is_empty()) {
        assert!(line.starts_with('#') || line.starts_with('[') || line.contains('='), "{line:?}");
    }
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn no_secret_is_in_a_unit_of_either_kind() {
    for spec in [node(&["--exit"]), node(&[]), serve(&[])] {
        for text in [unit(&spec, &alice()).expect("a unit"), super::text::unit(&spec)] {
            for secret in SECRET {
                assert!(!text.contains(secret), "{secret}: {text}");
            }
            assert!(!text.contains("EnvironmentFile"), "{text}");
        }
    }
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn an_exit_routes_and_iroh_add_netlink_with_a_comment_and_a_roost_relaxes_nothing() {
    for flag in ["--exit", "--routes", "--iroh"] {
        let words: &[&str] = if flag == "--routes" { &["--routes", "10.0.0.0/8"] } else { &[flag] };
        let text = unit(&node(words), &alice()).expect("a unit");
        let line = "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK";
        assert!(text.lines().any(|l| l == line), "{flag}: {text}");
        assert!(text.lines().any(|l| l.starts_with(&format!("# Relaxed for {flag}: AF_NETLINK"))), "{flag}: {text}");
    }
    let roost = unit(&node(&["--sshd"]), &alice()).expect("a unit");
    assert!(roost.contains("# A roost (--sshd)") && !roost.contains("Relaxed"), "{roost}");
    for line in HARDENED {
        assert!(roost.lines().any(|l| l == *line), "{line}: {roost}");
    }
    assert_eq!(Needs::of(&node(&[])), Needs::default());
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn serve_s_unit_leaves_out_each_line_that_a_session_needs_and_names_it() {
    let text = unit(&serve(&["--authorized-keys", "/home/alice/.ssh/keys"]), &alice()).expect("a unit");
    for line in ["User=alice", "Environment=HOME=/home/alice", "Environment=SHELL=/bin/bash"] {
        assert!(text.lines().any(|l| l == line), "{line}: {text}");
    }
    for kept in ["ProtectKernelTunables=yes", "ProtectClock=yes", "ProtectControlGroups=yes"] {
        assert!(text.lines().any(|l| l == kept), "{kept}: {text}");
    }
    for left in ["NoNewPrivileges=yes", "ProtectHome=tmpfs", "SystemCallFilter=@system-service"] {
        assert!(!text.lines().any(|l| l == left), "{left}: {text}");
        let named = format!(": {left}");
        assert!(text.lines().any(|l| l.starts_with("# Relaxed for serve, as ") && l.ends_with(&named)), "{text}");
    }
    assert!(!text.contains("StateDirectory") && !text.contains("BindPaths"), "{text}");
    assert!(text.contains("systemctl disable --now podssh-serve-lab.service"), "{text}");
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn the_directories_of_the_flags_files_are_let_through() {
    let spec = node(&[
        "--key",
        "/home/alice/keys/node.key",
        "--allow",
        "/home/alice/keys/allow",
        "--ca-file",
        "/etc/ssl/ca.pem",
        "--iroh-key",
        "/srv/podssh/iroh.key",
        "--pair-file",
        "/home/alice/.cache/podssh/lab.pair",
    ]);
    let text = unit(&spec, &alice()).expect("a unit");
    for line in ["BindPaths=-/home/alice/keys", "ReadWritePaths=-/srv/podssh"] {
        assert!(text.lines().any(|l| l == line), "{line}: {text}");
    }
    // One bind of a directory, written as a key is made there.
    assert!(!text.contains("BindReadOnlyPaths=-/home/alice/keys"), "{text}");
    // A file of /etc is read through ProtectSystem; the cache is bound already.
    assert!(!text.contains("Paths=-/etc/ssl"), "{text}");
    let read = unit(&node(&["--allow", "/home/alice/keys/allow"]), &alice()).expect("a unit");
    assert!(read.lines().any(|l| l == "BindReadOnlyPaths=-/home/alice/keys"), "{read}");
    assert_eq!(text.matches("/home/alice/.cache/podssh\n").count(), 1, "{text}");
    let spaced = node(&["--key", "/home/alice/my keys/node.key"]);
    assert_eq!(unit(&spaced, &alice()).expect_err("refused").code, EX_CONFIG);
}

#[test]
#[cfg(unix)]
fn the_socket_of_a_unix_route_under_a_home_is_let_through_read_only() {
    let hidden = node(&["api=unix-connect:/home/alice/run/api.sock", "db=unix-connect:/run/db.sock"]);
    let text = unit(&hidden, &alice()).expect("a unit");
    assert!(text.lines().any(|l| l == "BindReadOnlyPaths=-/home/alice/run"), "{text}");
    // ProtectSystem=strict leaves /run readable, and a connect only reads.
    assert!(!text.contains("Paths=-/run\n"), "{text}");
    let abstract_name = node(&["api=unix-connect:@podssh-api"]);
    assert!(!unit(&abstract_name, &alice()).expect("a unit").contains("Paths=-@"));
    let relative = node(&["api=unix-connect:run/api.sock"]);
    let refused = unit(&relative, &alice()).expect_err("refused");
    assert_eq!(refused.code, EX_USAGE, "{}", refused.message);
    assert!(refused.message.contains("absolute PATH"), "{}", refused.message);
}

#[test]
fn the_paths_of_a_system_unit_are_root_s_places() {
    assert_eq!(unit_path(Kind::Node, "lab"), Path::new("/etc/systemd/system/podssh-node-lab.service"));
    assert_eq!(state_dir(Kind::Node, "lab"), Path::new("/var/lib/podssh-node-lab"));
    assert_eq!(env_path(Kind::Node, "lab"), Path::new("/var/lib/podssh-node-lab/node-lab.env"));
}

/// The probes of a host, each given.
fn probes<'a>(
    euid: &'a dyn Fn() -> Option<u32>,
    systemd: &'a dyn Fn() -> bool,
    account: &'a dyn Fn(&str) -> Option<Account>,
    owner: &'a dyn Fn(&Path) -> Option<u32>,
) -> Probes<'a> {
    Probes { euid, systemd, account, owner }
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn each_missing_part_of_a_system_install_is_refused_with_its_words() {
    let root = || Some(0u32);
    let user = || Some(1000u32);
    let (yes, no) = (|| true, || false);
    let found = |name: &str| (name == "alice").then(alice);
    let nobody = |_: &str| -> Option<Account> { None };
    let theirs = |_: &Path| Some(1000u32);
    let missing = |_: &Path| -> Option<u32> { None };

    let all = probes(&root, &yes, &found, &theirs);
    assert_eq!(check(&all, "alice", "lab", true), Ok(alice()));

    let refusal = check(&probes(&user, &yes, &found, &theirs), "alice", "lab", true).expect_err("no root");
    assert_eq!(refusal.code, EX_NOPERM, "{}", refusal.message);
    assert!(refusal.message.contains("root"), "{}", refusal.message);

    let refusal = check(&probes(&root, &no, &found, &theirs), "alice", "lab", true).expect_err("no systemd");
    assert_eq!(refusal.code, EX_UNAVAILABLE, "{}", refusal.message);
    assert!(refusal.message.contains("/run/systemd/system"), "{}", refusal.message);

    let refusal = check(&probes(&root, &yes, &nobody, &theirs), "alice", "lab", true).expect_err("no entry");
    assert_eq!(refusal.code, EX_UNAVAILABLE, "{}", refusal.message);
    assert!(refusal.message.contains("/etc/passwd"), "{}", refusal.message);

    let refusal = check(&probes(&root, &yes, &found, &missing), "alice", "lab", true).expect_err("no cache");
    assert_eq!(refusal.code, EX_UNAVAILABLE, "{}", refusal.message);
    assert!(refusal.message.contains("/home/alice/.cache/podssh"), "{}", refusal.message);
    assert!(refusal.message.contains("podssh relay pair lab"), "{}", refusal.message);

    // A printed unit needs the entry alone: no root, no systemd, no cache.
    let printing = probes(&user, &no, &found, &missing);
    assert_eq!(check(&printing, "alice", "lab", false), Ok(alice()));
    let refusal = check(&probes(&user, &no, &nobody, &missing), "alice", "lab", false).expect_err("no entry");
    assert_eq!(refusal.code, EX_UNAVAILABLE, "{}", refusal.message);

    // root, and a name that a unit cannot hold, are usage errors.
    let as_root = |_: &str| Some(Account { uid: 0, ..alice() });
    assert_eq!(check(&probes(&root, &yes, &as_root, &theirs), "root", "lab", true).expect_err("root").code, EX_USAGE);
    assert_eq!(check(&all, "al ice", "lab", true).expect_err("a blank").code, EX_USAGE);
    let odd_home = |_: &str| Some(Account { home: PathBuf::from("/home/a b"), ..alice() });
    assert_eq!(check(&probes(&root, &yes, &odd_home, &theirs), "alice", "lab", true).expect_err("").code, EX_CONFIG);
}

#[test]
fn the_flags_of_a_system_unit_go_together() {
    assert!(flags(true, false, false, true, Some("alice")).is_ok());
    assert!(flags(false, true, false, true, None).is_ok(), "--uninstall --system needs no user");
    assert!(flags(false, false, true, true, Some("alice")).is_ok());
    assert!(flags(false, false, true, false, None).is_ok());
    for (install, uninstall, print, system, run_as, says) in [
        (true, false, true, false, None, "--print-unit"),
        (false, false, false, true, Some("alice"), "--system goes with"),
        (true, false, false, false, Some("alice"), "--run-as USER goes with --system"),
        (true, false, false, true, None, "--system needs --run-as"),
        (false, false, true, true, None, "--system needs --run-as"),
    ] {
        let refusal = flags(install, uninstall, print, system, run_as).expect_err(says);
        assert_eq!(refusal.code, EX_USAGE);
        assert!(refusal.message.contains(says), "{}", refusal.message);
    }
}

// A system unit is systemd's: its paths are Unix paths.
#[cfg(unix)]
#[test]
fn a_passwd_entry_is_read_as_the_c_library_reads_it() {
    let text = "# a comment\n+nis:x:1:1::/:/bin/sh\nroot:x:0:0:root:/root:/bin/bash\n\
                alice:x:1000:1001:Alice:/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:\nshort:x:3\n";
    let found = account_in(text, "alice").expect("alice");
    assert_eq!((found.uid, found.gid, found.home.as_path()), (1000, 1001, Path::new("/home/alice")));
    assert_eq!(found.shell.as_deref(), Some("/bin/bash"));
    assert_eq!(account_in(text, "bob").expect("bob").shell, None);
    assert!(account_in(text, "short").is_none() && account_in(text, "nis").is_none());
    assert!(account_in(text, "carol").is_none());
    assert!(user_name_ok("svc-podssh_1.a") && !user_name_ok("-x") && !user_name_ok("a b") && !user_name_ok(""));
    assert!(path_ok(Path::new("/home/alice")) && !path_ok(Path::new("home")) && !path_ok(Path::new("/a:b")));
    assert!(!path_ok(Path::new("/a%b")) && !path_ok(Path::new("/a\"b")));
}

#[test]
fn the_places_of_the_installer_are_not_carried_into_a_system_unit() {
    let text = "# head\nHTTPS_PROXY=http://proxy:3128\nXDG_CACHE_HOME=/root/.cache\nPODSSH_CACHE_DIR=/root/c\n";
    let (kept, dropped) = without(text, HOME_BOUND);
    assert_eq!(kept, "# head\nHTTPS_PROXY=http://proxy:3128\n");
    assert_eq!(dropped, ["XDG_CACHE_HOME", "PODSSH_CACHE_DIR"]);
}

/// `--print-unit` writes nothing: no file of variables where `--install`
/// would put one.
#[test]
fn a_printed_unit_writes_no_file() {
    let name = format!("t709-print-{}", std::process::id());
    let args = crate::node::NodeArgs {
        name: Some(name.clone()),
        targets: vec!["127.0.0.1:22".into()],
        print_unit: true,
        ..Default::default()
    };
    let planned = super::env::planned(Kind::Node, &name);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = super::print::node(&args, &mut out, &mut err);
    let (out, err) = (String::from_utf8_lossy(&out), String::from_utf8_lossy(&err));
    match planned {
        Ok(planned) => {
            assert_eq!(code, 0, "{err}");
            assert!(out.contains("ExecStart=") && out.contains(&format!("node {name} 127.0.0.1:22")), "{out}");
            // Its name: Windows quotes the path with each backslash doubled.
            let file = planned.file_name().unwrap_or_default().to_string_lossy().into_owned();
            assert!(out.contains(&file), "the file that --install writes: {out}");
            assert!(!planned.exists(), "{} was written", planned.display());
        }
        // A cache of none: the refusal, and nothing written either.
        Err(_) => assert_ne!(code, 0, "{out}"),
    }
}
