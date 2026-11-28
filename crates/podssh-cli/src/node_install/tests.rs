//! The texts of the services and the file of variables (T-121, T-393), on
//! each system: each quoting, the unit, the crontab's lines, the task, the
//! LaunchAgent, a tunnel's words, the lock of a run, and the variables
//! carried and refused.

use std::path::{Path, PathBuf};

use super::env::{body_in, body_of, parse, parse_in, CARRIED, SECRET};
use super::lock::{path_of, try_hold, Tried};
use super::ssh::{service_words, SERVICE_OPTIONS};
use super::text::{
    cron_lines, cron_mark, cron_table, plist, sh_word, systemd_word, task_xml, unit, windows_word, xml, UNIT_MARK,
    WATCHDOG,
};
use super::{Kind, Spec};

fn spec(args: &[&str]) -> Spec {
    Spec {
        kind: Kind::Node,
        name: "lab".into(),
        exe: PathBuf::from("/opt/pod ssh/podssh"),
        args: args.iter().map(|s| s.to_string()).collect(),
        dir: None,
        env_file: PathBuf::from("/c/node-lab.env"),
    }
}

/// A tunnel's service, run in `dir`.
fn tunnel(dir: &str) -> Spec {
    Spec { kind: Kind::Ssh, name: "bastion".into(), dir: Some(PathBuf::from(dir)), ..spec(&["ssh", "-N"]) }
}

#[test]
fn each_syntax_quotes_what_it_must() {
    assert_eq!(sh_word("node"), "node");
    assert_eq!(sh_word("a b"), "'a b'");
    assert_eq!(sh_word("it's"), "'it'\\''s'");
    assert_eq!(sh_word(""), "''");
    assert_eq!(systemd_word("/usr/bin/podssh"), "/usr/bin/podssh");
    assert_eq!(systemd_word("a b"), "\"a b\"");
    assert_eq!(systemd_word("100%"), "\"100%%\"");
    assert_eq!(systemd_word("$HOME"), "\"$$HOME\"");
    assert_eq!(systemd_word("say \"hi\"\\"), "\"say \\\"hi\\\"\\\\\"");
    assert_eq!(windows_word("C:\\podssh.exe"), "C:\\podssh.exe");
    assert_eq!(windows_word("C:\\Program Files\\x\\"), "\"C:\\Program Files\\x\\\\\"");
    assert_eq!(windows_word("a\"b"), "\"a\\\"b\"");
    assert_eq!(windows_word(""), "\"\"");
    assert_eq!(xml("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
}

#[test]
fn a_unit_runs_the_binary_by_its_path_with_the_node_s_words() {
    let unit = unit(&spec(&["node", "lab", "127.0.0.1:22", "--env-file", "/c/node-lab.env"])).unwrap();
    assert!(unit.starts_with(UNIT_MARK), "{unit}");
    assert!(unit.starts_with("# Written by podssh node.\n"), "{unit}");
    assert!(unit.contains("Type=exec\n"), "{unit}");
    let exec = "ExecStart=\"/opt/pod ssh/podssh\" node lab 127.0.0.1:22 --env-file /c/node-lab.env\n";
    assert!(unit.contains(exec), "{unit}");
    assert!(unit.contains("WantedBy=default.target"), "{unit}");
    assert!(!unit.contains("WorkingDirectory"), "a node's files are absolute: {unit}");
    assert!(pod_unit::systemd::audit(&unit, false).is_empty(), "{unit}");
}

/// T-393: a unit that always restarts, with no limit of starts, in the
/// section where systemd reads it; 77 restarts, 64 and 78 do not.
#[test]
fn a_unit_restarts_after_each_end_with_no_limit_of_starts() {
    let unit = unit(&spec(&["node", "lab"])).unwrap();
    let section = |name: &str| {
        let start = unit.find(&format!("[{name}]\n")).unwrap_or_else(|| panic!("[{name}]: {unit}"));
        let rest = &unit[start + name.len() + 3..];
        rest[..rest.find("\n[").unwrap_or(rest.len())].to_string()
    };
    let (head, service) = (section("Unit"), section("Service"));
    assert!(head.lines().any(|l| l == "StartLimitIntervalSec=0"), "{unit}");
    for line in ["Restart=always", "RestartSec=5", "RestartPreventExitStatus=64 78", "StartLimitInterval=0"] {
        assert!(service.lines().any(|l| l == line), "{line}: {unit}");
    }
    assert!(!unit.contains("on-failure"), "{unit}");
    assert!(!service.lines().any(|l| l.starts_with("RestartPreventExitStatus=") && l.contains("77")), "{unit}");
    // Each line that is not blank is a comment, a section or a key.
    for line in unit.lines().filter(|l| !l.is_empty()) {
        assert!(line.starts_with('#') || line.starts_with('[') || line.contains('='), "{line:?}");
    }
}

#[test]
fn a_tunnel_s_unit_runs_in_its_directory_and_names_its_own_removal() {
    let unit = unit(&tunnel("/home/me/100% here")).unwrap();
    assert!(unit.starts_with("# Written by podssh ssh.\n"), "{unit}");
    assert!(unit.contains("Description=podssh ssh bastion\n"), "{unit}");
    assert!(unit.contains("\nWorkingDirectory=-/home/me/100%% here\n"), "{unit}");
}

#[test]
fn the_crontab_gets_the_lines_of_the_name_and_loses_them_again() {
    let lines = cron_lines(&spec(&["node", "lab", "--env-file", "/c/100%/node-lab.env"])).unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    let (boot, watchdog) = (&lines[0], &lines[1]);
    // cron gives sh `%` for `\%`, before sh reads the quotes.
    let command = "'/opt/pod ssh/podssh' node lab --env-file '/c/100\\%/node-lab.env'";
    assert_eq!(boot, &format!("@reboot {command}"));
    assert_eq!(watchdog, &format!("*/5 * * * * {command}"));
    let mark = "# Written by podssh node: the lines below run the service podssh-node-lab";
    let before = "MAILTO=x\n0 * * * * backup\n";
    let (with, found) = cron_table(before, Kind::Node, "lab", Some(lines.as_slice()));
    assert!(!found);
    assert_eq!(with, format!("{before}{mark}\n{boot}\n{watchdog}\n"));
    // Again: the lines are replaced, never doubled.
    let new = ["@reboot new".to_string(), format!("{WATCHDOG} new")];
    let (again, found) = cron_table(&with, Kind::Node, "lab", Some(new.as_slice()));
    assert!(found && again.matches("@reboot").count() == 1 && again.matches(WATCHDOG).count() == 1, "{again}");
    assert!(again.contains("@reboot new\n*/5 * * * * new\n"), "{again}");
    // The lines of another NAME, and of a tunnel of the same NAME, stay.
    let (both, _) = cron_table(&again, Kind::Node, "other", Some(["@reboot other".to_string()].as_slice()));
    let (all, _) = cron_table(&both, Kind::Ssh, "lab", Some(["@reboot tunnel".to_string()].as_slice()));
    let (rest, found) = cron_table(&all, Kind::Node, "lab", None);
    assert!(found && rest.contains("@reboot other") && rest.contains("@reboot tunnel"), "{rest}");
    assert!(!rest.contains("new"), "{rest}");
    let (rest, _) = cron_table(&rest, Kind::Ssh, "lab", None);
    assert_eq!(cron_table(&rest, Kind::Node, "other", None).0, before);
    // A line below the mark (new or pre-pod-unit) that is not @reboot is the user's.
    for heading in [mark.to_string(), cron_mark(Kind::Node, "lab")] {
        let edited = format!("{heading}\n0 1 * * * mine\n");
        assert_eq!(cron_table(&edited, Kind::Node, "lab", None), ("0 1 * * * mine\n".to_string(), true));
    }
}

/// The tables that T-121 and T-393 wrote, before `pod-unit`, are found and
/// replaced via `older_marks`; a user line after them, even each 5 minutes,
/// stays.
#[test]
fn the_line_of_an_earlier_install_is_replaced_and_the_user_s_next_line_stays() {
    let lines = cron_lines(&spec(&["node", "lab"])).unwrap();
    for old in [
        "# podssh node lab --install wrote the line below; podssh node lab --uninstall removes it\n\
         @reboot /usr/bin/podssh node lab --env-file /c/node-lab.env\n\
         */5 * * * * /usr/bin/mine\n",
        "# podssh node lab --install wrote the lines below; podssh node lab --uninstall removes them\n\
         @reboot /usr/bin/podssh node lab --env-file /c/node-lab.env\n\
         */5 * * * * /usr/bin/podssh node lab --env-file /c/node-lab.env\n\
         */5 * * * * /usr/bin/mine\n",
    ] {
        let (table, found) = cron_table(old, Kind::Node, "lab", Some(lines.as_slice()));
        assert!(found, "{table}");
        assert!(table.starts_with("*/5 * * * * /usr/bin/mine\n"), "{table}");
        assert_eq!(table.matches("@reboot").count(), 1, "{table}");
    }
}

#[test]
fn a_tunnel_s_lines_change_to_its_directory_first() {
    let lines = cron_lines(&tunnel("/home/me/it's")).unwrap();
    assert_eq!(lines[0], "@reboot cd '/home/me/it'\\''s' 2>/dev/null; '/opt/pod ssh/podssh' ssh -N");
    assert!(lines[1].starts_with("*/5 * * * * cd '/home/me/it'\\''s' 2>/dev/null; "), "{}", lines[1]);
}

#[test]
fn the_task_runs_as_this_user_at_its_logon_with_no_privilege() {
    let task = task_xml(&spec(&["node", "lab", "--env-file", "C:\\Users\\a b\\node-lab.env"]), "HOST\\a&b").unwrap();
    assert!(task.contains("Written by podssh node."), "{task}");
    assert_eq!(task.matches("<UserId>HOST\\a&amp;b</UserId>").count(), 2, "{task}");
    assert!(task.contains("<LogonType>InteractiveToken</LogonType>"), "{task}");
    assert!(task.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{task}");
    assert!(task.contains("<Command>/opt/pod ssh/podssh</Command>"), "{task}");
    let arguments = "<Arguments>node lab --env-file &quot;C:\\Users\\a b\\node-lab.env&quot;</Arguments>";
    assert!(task.contains(arguments), "{task}");
    // T-393: each 5 minutes too, never beside a running instance.
    assert!(task.contains("<TimeTrigger><Repetition><Interval>PT5M</Interval>"), "{task}");
    assert!(task.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"), "{task}");
    assert!(!task.contains("WorkingDirectory"), "{task}");
    let task = task_xml(&tunnel("C:\\Users\\me"), "HOST\\me").unwrap();
    assert!(task.contains("</Arguments><WorkingDirectory>C:\\Users\\me</WorkingDirectory></Exec>"), "{task}");
}

/// The LaunchAgent is XML that a parser reads back to the same program and
/// words, with the keys that keep it running.
#[test]
fn the_launch_agent_reads_back_as_its_program_and_keeps_it_alive() {
    let agent = spec(&["node", "lab", "a&b <c>", "--env-file", "/c/node-lab.env"]);
    let text = plist(&agent, "dev.podssh.node.lab", Path::new("/c/node-lab.log")).unwrap();
    let options = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(&text, options).unwrap_or_else(|e| panic!("{e}: {text}"));
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "plist");
    let dict = root.children().find(|n| n.is_element()).unwrap();
    assert_eq!(dict.tag_name().name(), "dict");
    let items: Vec<roxmltree::Node> = dict.children().filter(|n| n.is_element()).collect();
    let value = |key: &str| {
        let at = items.iter().position(|n| n.tag_name().name() == "key" && n.text() == Some(key));
        items[at.unwrap_or_else(|| panic!("{key}: {text}")) + 1]
    };
    assert_eq!(value("Label").text(), Some("dev.podssh.node.lab"));
    let array = value("ProgramArguments");
    let program: Vec<&str> = array.children().filter(|n| n.is_element()).filter_map(|n| n.text()).collect();
    assert_eq!(program, ["/opt/pod ssh/podssh", "node", "lab", "a&b <c>", "--env-file", "/c/node-lab.env"]);
    assert_eq!(value("KeepAlive").tag_name().name(), "true");
    assert_eq!(value("RunAtLoad").tag_name().name(), "true");
    assert_eq!(value("ThrottleInterval").text(), Some("5"));
    assert_eq!(value("ExitTimeOut").text(), Some("90"));
    assert_eq!(value("Umask").text(), Some("63"));
    assert_eq!(value("StandardErrorPath").text(), Some("/c/node-lab.log"));
    assert!(!items.iter().any(|n| n.text() == Some("WorkingDirectory")), "{text}");
    let text = plist(&tunnel("/Users/me"), "dev.podssh.ssh.bastion", Path::new("/c/ssh-bastion.log")).unwrap();
    assert!(text.contains("  <key>WorkingDirectory</key>\n  <string>/Users/me</string>\n"), "{text}");
}

/// T-820: a 128-character node name (podssh's maximum) and a name holding `--`
/// pass `pod-unit` on every user form; a user unit with `--exit` gains
/// `AF_NETLINK` and a `serve` user unit relaxes its session seccomp lines.
#[test]
fn pod_unit_renders_long_names_double_dash_names_and_user_hardening() {
    for name in ["a".repeat(128), "my--node".to_string()] {
        let s = Spec { name: name.clone(), ..spec(&["node", &name, "--exit"]) };
        let u = unit(&s).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(u.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"), "{u}");
        assert!(cron_lines(&s).is_ok(), "{name}");
        assert!(task_xml(&s, "HOST\\me").is_ok(), "{name}");
        assert!(plist(&s, &format!("dev.podssh.node.{name}"), Path::new("/c/n.log")).is_ok(), "{name}");
    }
    let serve_spec = Spec { kind: Kind::Serve, ..spec(&["serve", "lab"]) };
    let u = unit(&serve_spec).unwrap();
    assert!(!u.lines().any(|l| l == "NoNewPrivileges=yes" || l == "SystemCallFilter=@system-service"), "{u}");
    assert!(pod_unit::systemd::audit(&u, false).is_empty(), "{u}");
}

/// A tunnel's service runs the words as typed, after the options that a
/// service needs and its file of variables; `--install NAME` goes in each
/// spelling, and a word after `--` stays whatever it is.
#[test]
fn a_tunnel_s_words_are_the_typed_ones_but_install() {
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let env = Path::new("/c/ssh-bastion.env");
    let mut head = vec!["ssh".to_string()];
    for option in SERVICE_OPTIONS {
        head.extend(["-o".to_string(), option.to_string()]);
    }
    head.extend(["--env-file".to_string(), "/c/ssh-bastion.env".to_string()]);
    // A tunnel's service never gives up (T-391), once.
    let forever = words(&["--persist-forever"]);
    let typed = words(&["ssh", "-N", "--install", "bastion", "-R", "2222:127.0.0.1:22", "--persist", "me@host"]);
    let want =
        [head.clone(), forever.clone(), words(&["-N", "-R", "2222:127.0.0.1:22", "--persist", "me@host"])].concat();
    assert_eq!(service_words(&typed, env), want);
    let typed = words(&["connect", "--install=bastion", "-N", "--persist", "--", "--install", "x"]);
    let mut want = [head.clone(), forever, words(&["-N", "--persist", "--", "--install", "x"])].concat();
    want[0] = "connect".into();
    assert_eq!(service_words(&typed, env), want);
    let typed = words(&["ssh", "-N", "--persist-forever", "--install", "b", "--persist", "me@host"]);
    let want = [head, words(&["-N", "--persist-forever", "--persist", "me@host"])].concat();
    assert_eq!(service_words(&typed, env), want);
    for option in ["BatchMode=yes", "ForkAfterAuthentication=no", "ControlPath=none", "ExitOnForwardFailure=yes"] {
        assert!(SERVICE_OPTIONS.contains(&option), "{option}");
    }
}

/// One run of a service at a time: a second try of the lock is refused
/// while the first holds it, and taken once the first lets it go.
#[test]
fn a_second_try_of_a_lock_is_refused_until_the_first_lets_it_go() {
    let dir = std::env::temp_dir().join(format!("podssh-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = path_of(&dir.join("node-lab.env"));
    assert_eq!(path, dir.join("node-lab.env.lock"));
    let first = match try_hold(&path) {
        Ok(Tried::Held(file)) => file,
        other => panic!("{other:?}"),
    };
    match try_hold(&path) {
        // The pid in the file, where the system lets another handle read it.
        Ok(Tried::Taken(pid)) => assert!(pid.is_none() || pid == Some(std::process::id()), "{pid:?}"),
        other => panic!("taken, not {other:?}"),
    }
    drop(first);
    assert!(matches!(try_hold(&path), Ok(Tried::Held(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_file_of_variables_carries_the_proxy_and_never_a_token() {
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let env = [
        pair("https_proxy", "http://proxy.example:3128"),
        pair("PODSSH_RELAY_TOKEN", "a-token"),
        pair("NO_PROXY", "a\nb"),
        pair("PODSSH_CACHE_DIR", "/c"),
        pair("PODSSH_OFFLINE", "1"),
        pair("PATH", "/bin"),
        pair("EDITOR", "vi"),
    ];
    let (text, left) = body_of(env.into_iter());
    assert!(text.contains("\nhttps_proxy=http://proxy.example:3128\n"), "{text}");
    assert!(text.contains("\nPODSSH_CACHE_DIR=/c\n"), "{text}");
    for absent in ["a-token", "NO_PROXY", "PODSSH_OFFLINE", "PATH", "EDITOR"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    assert_eq!(left, ["PODSSH_RELAY_TOKEN"]);
    // What it wrote, it reads back, in the order of the names.
    let read = parse(&text).unwrap();
    assert_eq!(read, [pair("PODSSH_CACHE_DIR", "/c"), pair("https_proxy", "http://proxy.example:3128")]);
    let refused = [("PODSSH_RELAY_TOKEN=x", "is a token"), ("EDITOR=vi", "not a variable"), ("words", "NAME=VALUE")];
    for (bad, why) in refused {
        assert!(parse(bad).unwrap_err().contains(why), "{bad}");
    }
    assert_eq!(parse("# c\n\nPODSSH_RELAY=r.example:443\r\n").unwrap(), [pair("PODSSH_RELAY", "r.example:443")]);
    assert!(SECRET.iter().all(|s| !CARRIED.contains(s)));
}

/// T-718: a service carries the files of a service token of Cloudflare
/// Access, paths alone, and never the secret of its variable.
#[test]
fn the_file_of_variables_carries_the_files_of_access_and_never_its_secret() {
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let env = [
        pair("PODSSH_CF_ACCESS_CLIENT_ID_FILE", "/etc/podssh/access-id"),
        pair("PODSSH_CF_ACCESS_CLIENT_SECRET_FILE", "/etc/podssh/access-secret"),
        pair("PODSSH_CF_ACCESS_CLIENT_SECRET", "the-secret-of-this-test"),
    ];
    let (text, left) = body_of(env.into_iter());
    assert!(text.contains("\nPODSSH_CF_ACCESS_CLIENT_ID_FILE=/etc/podssh/access-id\n"), "{text}");
    assert!(text.contains("\nPODSSH_CF_ACCESS_CLIENT_SECRET_FILE=/etc/podssh/access-secret\n"), "{text}");
    assert!(!text.contains("the-secret-of-this-test"), "{text}");
    assert_eq!(left, ["PODSSH_CF_ACCESS_CLIENT_SECRET"]);
    assert_eq!(parse(&text).unwrap().len(), 2, "it reads the paths back");
}

/// A retired name in a service's file (T-634), on the row of the tests: the
/// reader refuses it with its line and what replaced it, an empty value
/// passes, and the install leaves it out.
#[test]
fn a_retired_variable_in_an_env_file_is_refused_with_its_line() {
    use crate::retired::tests::ROW;
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let text = "# c\nPODSSH_RELAY=r.example:443\nPODSSH_RETIRED_FOR_TESTS=yes\n";
    let why = parse_in(text, &[ROW]).unwrap_err();
    assert!(why.starts_with("line 3: PODSSH_RETIRED_FOR_TESTS is no longer read (since v0.0.0)"), "{why}");
    assert!(why.contains("use PODSSH_RELAY instead; remove it"), "{why}");
    let empty = parse_in("PODSSH_RETIRED_FOR_TESTS=\n", &[ROW]).unwrap();
    assert_eq!(empty, [pair("PODSSH_RETIRED_FOR_TESTS", "")]);
    // With the release's table, the same file reads as before.
    assert_eq!(parse(text).unwrap().len(), 2);
    let set = [pair("PODSSH_RETIRED_FOR_TESTS", "yes"), pair("PODSSH_CACHE_DIR", "/c")];
    let (written, left) = body_in(set.into_iter(), &[ROW]);
    assert!(!written.contains("PODSSH_RETIRED_FOR_TESTS") && written.contains("\nPODSSH_CACHE_DIR=/c\n"), "{written}");
    assert_eq!(left, ["PODSSH_RETIRED_FOR_TESTS"]);
}

/// T-718: a node's service keeps its hosts of Cloudflare Access, by name;
/// their credentials are files of the file of variables, never words.
/// Units carrying `--access-host` keep exit 77 from restarting in systemd.
#[test]
fn the_service_of_a_node_keeps_its_hosts_of_access() {
    let args = crate::node_args::NodeArgs {
        access_hosts: vec!["edge.example".into(), "a.example,b.example".into()],
        targets: vec!["127.0.0.1:22".into()],
        ..Default::default()
    };
    let words = super::text::service_args(&args, "lab", Path::new("/e/node-lab.env")).unwrap();
    let at = words.iter().position(|w| w == "--access-host").expect("the flag");
    assert_eq!(&words[at..at + 4], ["--access-host", "edge.example", "--access-host", "a.example,b.example"]);

    let access_spec = spec(&["node", "lab", "127.0.0.1:22", "--access-host", "edge.example"]);
    let user_unit = unit(&access_spec).expect("a user unit");
    assert!(user_unit.contains("RestartPreventExitStatus=64 77 78\n"), "{user_unit}");
    let account = super::system::Account {
        user: "alice".into(),
        uid: 1000,
        gid: 1000,
        home: PathBuf::from("/home/alice"),
        shell: None,
    };
    let sys_unit = super::system_text::unit(&access_spec, &account).expect("a system unit");
    assert!(sys_unit.contains("RestartPreventExitStatus=64 77 78\n"), "{sys_unit}");
}
