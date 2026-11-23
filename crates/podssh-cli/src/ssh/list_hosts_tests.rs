//! The projection of `--list-hosts` (T-832): one table of aliases over one
//! config with an `Include`, wildcard and negated patterns, a `HostName`
//! with `%h`, a jump and a block that resolves nothing; each row holds what
//! `podssh ssh ALIAS` resolves, read through the same resolve.

use std::path::{Path, PathBuf};

use super::*;

/// A scratch home of one test, private as a user's home is, removed when
/// dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-list-hosts-{name}-{}", std::process::id()));
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

    /// `~/.ssh/config` of this home, and no system file.
    fn env(&self) -> Env {
        Env { home: Some(self.0.clone()), user: Some("lu".into()), ..Env::default() }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const CONFIG: &str = "Include conf.d/*\n\
    Host web1 web2\n    HostName %h.example.org\n    User admin\n    Port 2222\n\
    Host *.example.org !bad.example.org\n    User wild\n\
    Host db\n    HostName db.internal\n    ProxyJump bastion\n    IdentityFile ~/.ssh/db_key\n\
    Host bastion\n    HostName Bastion.Example.Net\n\
    Host -bad\n\
    Host *\n    User everyone\n";

const EXTRA: &str = "Host extra1 extra?\n    HostName extra.internal\n";

fn defaults(home: &Path) -> Vec<String> {
    podssh_ssh::options::default_identity_files(home).iter().map(|p| p.display().to_string()).collect()
}

#[test]
fn each_alias_is_projected_as_a_connection_to_it_resolves() {
    let h = Home::new("table");
    h.file(".ssh/conf.d/extra", EXTRA);
    h.file(".ssh/config", CONFIG);
    let records = records(&SshArgs::default(), &h.env()).expect("a list");
    let key = h.0.join(".ssh").join("db_key").display().to_string();
    // (alias, host, port, user, identity files, jump); a pattern is no row.
    #[rustfmt::skip]
    let table = [
        ("extra1", "extra.internal", 22, "everyone", defaults(&h.0), None),
        ("web1", "web1.example.org", 2222, "admin", defaults(&h.0), None),
        ("web2", "web2.example.org", 2222, "admin", defaults(&h.0), None),
        ("db", "db.internal", 22, "everyone", vec![key], Some("bastion")),
        ("bastion", "bastion.example.net", 22, "everyone", defaults(&h.0), None),
    ];
    let aliases: Vec<&str> = records.iter().map(|r| r.alias.as_str()).collect();
    assert_eq!(aliases, ["extra1", "web1", "web2", "db", "bastion", "-bad"]);
    // One separator, as Windows joins `~/.ssh/db_key` with its own.
    let slashed = |ids: Vec<String>| -> Vec<String> { ids.iter().map(|p| p.replace('\\', "/")).collect() };
    for (record, (alias, host, port, user, ids, jump)) in records.iter().zip(table) {
        let want = Fields {
            host: host.into(),
            port,
            user: user.into(),
            identity_files: slashed(ids),
            proxy_jump: jump.map(str::to_string),
        };
        let mut have = record.resolved.clone().unwrap_or_else(|why| panic!("{alias}: {why}"));
        have.identity_files = slashed(have.identity_files);
        assert_eq!(have, want, "{alias}");
    }
    // A block that resolves nothing is a record that says why, as the run
    // would say it; the list goes on.
    let bad = records.last().expect("-bad");
    let why = bad.resolved.as_ref().expect_err("-bad resolves nothing");
    assert!(why.contains("cannot start with '-'"), "{why}");
    // The same resolve as `podssh ssh ALIAS`: the two cannot differ.
    for record in &records[..5] {
        let typed = SshArgs { destination: Some(record.alias.clone()), ..SshArgs::default() };
        let resolved = super::super::resolve::resolve(&typed, &h.env()).expect("a typed alias");
        let fields = record.resolved.as_ref().expect("fields");
        assert_eq!(
            (&resolved.options.user, resolved.options.destination.port, &resolved.shown.hostname),
            (&fields.user, fields.port, &fields.host),
            "{}",
            record.alias
        );
    }
}

#[test]
fn the_json_has_one_shape_and_no_secret() {
    let ok = Record {
        alias: "db".into(),
        resolved: Ok(Fields {
            host: "db.internal".into(),
            port: 2200,
            user: "u".into(),
            identity_files: vec!["/k".into()],
            proxy_jump: Some("bastion".into()),
        }),
    };
    let bad = Record { alias: "-bad".into(), resolved: Err("no".into()) };
    let value = json(&[ok.clone(), bad]);
    let rows = value.as_array().expect("an array");
    let keys = ["alias", "host", "port", "user", "identity_files", "proxy_jump", "error"];
    for row in rows {
        let object = row.as_object().expect("an object");
        let mut have: Vec<&str> = object.keys().map(String::as_str).collect();
        have.sort_unstable();
        let mut want = keys.to_vec();
        want.sort_unstable();
        assert_eq!(have, want, "{row}");
    }
    assert_eq!(rows[0]["port"], 2200);
    assert_eq!(rows[0]["error"], Value::Null);
    assert_eq!(rows[1]["host"], Value::Null);
    assert_eq!(rows[1]["error"], "no");
    // The picker's words for the same record.
    let Ok(fields) = &ok.resolved else { unreachable!() };
    assert_eq!(detail(fields), "u@db.internal:2200 via bastion");
    let six = Fields { host: "fe80::1".into(), port: 22, ..fields.clone() };
    assert_eq!(detail(&Fields { proxy_jump: None, ..six.clone() }), "u@fe80::1");
    assert_eq!(detail(&Fields { port: 2, proxy_jump: None, ..six }), "u@[fe80::1]:2");
}

#[test]
fn a_file_that_cannot_be_read_is_78_and_a_destination_is_64() {
    let h = Home::new("unread");
    // A directory named by -F, and a file that is not there.
    let dir = h.0.join(".ssh").display().to_string();
    let missing = h.0.join("nothing-here").display().to_string();
    for file in [dir, missing] {
        let args = SshArgs { config: Some(file.clone()), list_hosts: true, ..SshArgs::default() };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&args, &h.env(), &mut out, &mut err), 78, "{file}");
        assert!(out.is_empty(), "nothing on stdout for {file}");
        assert!(String::from_utf8_lossy(&err).contains(&file), "{}", String::from_utf8_lossy(&err));
    }
    let args = SshArgs { destination: Some("web1".into()), list_hosts: true, ..SshArgs::default() };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&args, &h.env(), &mut out, &mut err), 64);
    // No file at all is an empty list, exit 0.
    let none = SshArgs { config: Some("none".into()), list_hosts: true, ..SshArgs::default() };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&none, &h.env(), &mut out, &mut err), 0);
    assert_eq!(String::from_utf8_lossy(&out).trim(), "[]");
}
