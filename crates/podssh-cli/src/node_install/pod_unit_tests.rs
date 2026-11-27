//! What `pod-unit` makes of podssh's real units (T-820): public keys and
//! fingerprints of `--net-owner` and `--authorized-key` pass the secret scan;
//! a token is still refused; and `pod_unit::install::{install, remove,
//! install_system, remove_system}` recognize and cleanly replace/remove units
//! written by pre-`pod-unit` podssh while refusing foreign files.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pod_core::process::Ran;
use pod_unit::install::{install, install_system, remove, remove_system};
use pod_unit::{Form, Host, Places, Removed, SystemPlaces};
use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::ssh_key::HashAlg;

use super::system::Account;
use super::text::{self, PLIST_MARK, UNIT_MARK};
use super::{system_text, Kind, Spec};

fn spec(kind: Kind, name: &str, words: &[String]) -> Spec {
    Spec {
        kind,
        name: name.to_string(),
        exe: PathBuf::from("/usr/local/bin/podssh"),
        args: words.to_vec(),
        dir: None,
        env_file: PathBuf::from("/c/node-lab.env"),
    }
}

/// Each of 50 random keys, in each form that the flags take, passes through
/// `node_install`'s real `pod_unit` builders.
#[test]
fn pod_unit_passes_public_keys_fingerprints_and_podssh_s_older_marks() {
    for n in 0..50 {
        let key = generate(KeyKind::Ed25519, "owner@lab").unwrap();
        let line = key.public_key().to_openssh().unwrap();
        let print = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let words: Vec<String> = ["node", "lab", "--net-url", "https://example.test/net.json", "--net-owner", &print]
            .map(String::from)
            .into();
        text::pod_unit(&spec(Kind::Node, "lab", &words))
            .unwrap()
            .check()
            .unwrap_or_else(|e| panic!("key {n}, the fingerprint: {e}"));
        let words: Vec<String> = ["node", "lab", "--net-owner", &line].map(String::from).into();
        text::pod_unit(&spec(Kind::Node, "lab", &words))
            .unwrap()
            .check()
            .unwrap_or_else(|e| panic!("key {n}, the key: {e}"));
        let words: Vec<String> = ["serve", "lab", "--authorized-key", &line].map(String::from).into();
        text::pod_unit(&spec(Kind::Serve, "lab", &words))
            .unwrap()
            .check()
            .unwrap_or_else(|e| panic!("key {n}, serve's key: {e}"));
    }
}

/// The control: a token among the words is still refused, by its rule and
/// never by its text; and an older mark shorter than 8 characters is
/// refused, which none of podssh's is.
#[test]
fn pod_unit_still_refuses_a_token_and_a_short_older_mark() {
    let token = format!("ghp_{}", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI2k");
    let words: Vec<String> = ["node", "lab", "--relay-addr", &token].map(String::from).into();
    let refused = text::unit(&spec(Kind::Node, "lab", &words)).unwrap_err().message;
    assert!(refused.contains("GitHub token"), "{refused}");
    assert!(!refused.contains(&token), "the refusal names the rule, never the word: {refused}");
    let words: Vec<String> = vec!["node".into(), "lab".into()];
    let short =
        text::pod_unit(&spec(Kind::Node, "lab", &words)).unwrap().older_mark("podssh").check().unwrap_err().to_string();
    assert!(short.contains("older mark"), "{short}");
}

struct FakeHost {
    admin: bool,
    calls: Mutex<Vec<String>>,
}

impl FakeHost {
    fn new(admin: bool) -> FakeHost {
        FakeHost { admin, calls: Mutex::new(Vec::new()) }
    }
}

impl Host for FakeHost {
    fn run(&self, program: &str, args: &[&str], _input: Option<&[u8]>) -> Result<Ran, pod_core::Failure> {
        self.calls.lock().unwrap().push(format!("{program} {}", args.join(" ")));
        let stdout = if program == "id" && args.first() == Some(&"-u") { "1000\n".to_string() } else { String::new() };
        Ok(Ran { code: Some(0), stdout, stderr: String::new() })
    }

    fn admin(&self) -> bool {
        self.admin
    }

    fn systemd_booted(&self) -> bool {
        true
    }
}

/// A unit or plist written by pre-`pod-unit` podssh is upgraded in place and
/// removed cleanly via `older_marks`; a foreign file is refused and kept.
#[test]
fn pod_unit_upgrades_older_podssh_units_and_refuses_foreign_files() {
    let root = std::env::temp_dir().join(format!("podssh-pod-unit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let places = Places::of_home(&root, &root.join("scratch"), 1000, "");
    let sys_places = SystemPlaces { systemd: root.join("etc"), launch_daemons: root.join("daemons") };
    std::fs::create_dir_all(&places.systemd_user).unwrap();
    std::fs::create_dir_all(&places.launch_agents).unwrap();
    std::fs::create_dir_all(&sys_places.systemd).unwrap();

    let host = FakeHost::new(true);
    let words = ["node", "lab", "127.0.0.1:22", "--env-file", "/c/node-lab.env"].map(String::from);
    let user_unit = text::pod_unit(&spec(Kind::Node, "lab", &words)).unwrap();

    // Older pre-pod-unit systemd user unit is replaced and then removed.
    let unit_file = places.systemd_user.join("podssh-node-lab.service");
    std::fs::write(&unit_file, format!("{UNIT_MARK}node lab --install; podssh node lab --uninstall removes it.\n"))
        .unwrap();
    install(&user_unit, Form::Systemd, &places, &host).expect("replaces older podssh unit");
    let replaced = std::fs::read_to_string(&unit_file).unwrap();
    assert!(replaced.starts_with("# Written by podssh node.\n"), "{replaced}");
    assert!(matches!(remove(&user_unit, Form::Systemd, &places, &host).unwrap(), Removed::Done(_)));
    assert!(!unit_file.exists());

    // Foreign unit file is refused and untouched.
    std::fs::write(&unit_file, "# Written by someone else.\n").unwrap();
    let refused = install(&user_unit, Form::Systemd, &places, &host).unwrap_err();
    assert_eq!(refused.class, pod_core::Class::Config);
    assert_eq!(std::fs::read_to_string(&unit_file).unwrap(), "# Written by someone else.\n");

    // Older pre-pod-unit LaunchAgent plist is recognized and removed.
    let plist_file = places.launch_agents.join("dev.podssh.node.lab.plist");
    std::fs::write(&plist_file, format!("{PLIST_MARK}; its uninstall of the service removes this file. -->\n"))
        .unwrap();
    assert!(matches!(remove(&user_unit, Form::Launchd, &places, &host).unwrap(), Removed::Done(_)));
    assert!(!plist_file.exists());

    // System unit: older pre-pod-unit system unit is replaced via install_system and removed via remove_system.
    let account = Account {
        user: "alice".into(),
        uid: 1000,
        gid: 1000,
        home: PathBuf::from("/home/alice"),
        shell: Some("/bin/bash".into()),
    };
    let sys_unit = system_text::pod_unit(&spec(Kind::Node, "lab", &words), &account).unwrap();
    let sys_file = sys_places.systemd.join("podssh-node-lab.service");
    std::fs::write(&sys_file, format!("{UNIT_MARK}node lab --install --system --run-as alice.\n")).unwrap();
    install_system(&sys_unit, Form::Systemd, &sys_places, &host).expect("install_system replaces older unit");
    let sys_text = std::fs::read_to_string(&sys_file).unwrap();
    assert!(sys_text.starts_with("# Written by podssh node.\n") && sys_text.contains("User=alice\n"), "{sys_text}");
    assert!(pod_unit::systemd::audit(&sys_text, true).is_empty(), "{sys_text}");
    let rm_unit = text::base_unit(Kind::Node, "lab", Path::new("/usr/bin/podssh")).system(None);
    assert!(matches!(remove_system(&rm_unit, Form::Systemd, &sys_places, &host).unwrap(), Removed::Done(_)));
    assert!(!sys_file.exists());

    let calls = host.calls.lock().unwrap();
    assert!(calls.iter().any(|c| c == "systemctl --user restart podssh-node-lab.service"), "{calls:?}");
    assert!(calls.iter().any(|c| c == "launchctl bootout gui/1000/dev.podssh.node.lab"), "{calls:?}");
    assert!(calls.iter().any(|c| c == "systemctl restart podssh-node-lab.service"), "{calls:?}");
    assert!(calls.iter().any(|c| c == "systemctl disable --now podssh-node-lab.service"), "{calls:?}");

    let _ = std::fs::remove_dir_all(&root);
}
