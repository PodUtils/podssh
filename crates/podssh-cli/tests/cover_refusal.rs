//! The refusals of `podssh relay serve --cover` at the start (#225, T-768
//! and podnet#491): a wildcard certificate is refused with or without a
//! cover, and a cover script that is missing or has no date is refused with
//! the configuration exit (78), before the listener binds.

#![cfg(unix)]

mod serve_certs;

use std::process::{Command, Stdio};

use serve_certs::{ca_and_leaf_for, podssh, replace, Scratch};

fn run(dir: &std::path::Path, args: &[String]) -> std::process::Output {
    let mut cmd: Command = podssh(dir);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.output().expect("the podssh binary runs")
}

/// A scratch directory with a certificate, a site and a socket path.
struct Place {
    s: Scratch,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    site: std::path::PathBuf,
    socket: std::path::PathBuf,
}

impl Place {
    fn new(tag: &str, names: &[&str]) -> Place {
        let s = Scratch(std::env::temp_dir().join(format!(
            "podssh-cover-refusal-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )));
        std::fs::create_dir_all(s.0.join("site")).unwrap();
        std::fs::write(s.0.join("site/index.html"), b"<html><body>cover</body></html>").unwrap();
        let (_, leaf, key) = ca_and_leaf_for(tag, names);
        let (cert, key_file) = (s.0.join("cert.pem"), s.0.join("key.pem"));
        replace(&cert, &leaf);
        replace(&key_file, &key);
        Place { cert, key: key_file, site: s.0.join("site"), socket: s.0.join("control.sock"), s }
    }

    fn serve(&self) -> Vec<String> {
        [
            "relay".to_string(),
            "serve".to_string(),
            "--listen".to_string(),
            "127.0.0.1:0".to_string(),
            "--cert".to_string(),
            self.cert.display().to_string(),
            "--key".to_string(),
            self.key.display().to_string(),
        ]
        .to_vec()
    }

    fn cover(&self, script: Option<&std::path::Path>) -> Vec<String> {
        let mut args = self.serve();
        args.extend([
            "--cover".to_string(),
            self.site.display().to_string(),
            "--control-socket".to_string(),
            self.socket.display().to_string(),
        ]);
        if let Some(script) = script {
            args.extend(["--cover-script".to_string(), script.display().to_string()]);
        }
        args
    }
}

#[test]
fn a_wildcard_certificate_is_refused_with_or_without_a_cover() {
    let place = Place::new("wildcard", &["*.example.org"]);
    for (name, args) in [("without a cover", place.serve()), ("with a cover", place.cover(None))] {
        let out = run(&place.s.0, &args);
        assert_eq!(out.status.code(), Some(78), "{name}: {}", String::from_utf8_lossy(&out.stderr));
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains("wildcard *.example.org"), "{name}: {said}");
        assert!(said.contains("--cover"), "{name}: {said}");
    }
}

#[test]
fn a_missing_or_undated_cover_script_is_refused_at_the_start() {
    let place = Place::new("script", &["relay-a.test"]);
    let missing = place.s.0.join("no-such-script.toml");
    let out = run(&place.s.0, &place.cover(Some(&missing)));
    assert_eq!(out.status.code(), Some(78), "{}", String::from_utf8_lossy(&out.stderr));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("is not there"), "{said}");

    let undated = place.s.0.join("undated.toml");
    std::fs::write(&undated, "cover_version = \"pod-cover test\"\n[split]\nmin = 16\nmax = 4096\n").unwrap();
    let out = run(&place.s.0, &place.cover(Some(&undated)));
    assert_eq!(out.status.code(), Some(78), "{}", String::from_utf8_lossy(&out.stderr));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("has no date"), "{said}");
}

#[test]
fn a_cover_name_without_a_cover_is_a_usage_error() {
    let place = Place::new("name", &["relay-a.test"]);
    let mut args = place.serve();
    args.extend(["--cover-name".to_string(), "relay-a.test".to_string()]);
    let out = run(&place.s.0, &args);
    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--cover-name goes with --cover"), "{out:?}");
}

/// An SSH client of the covered port would name the role, so the two are
/// refused together: the cover answers before any role route.
#[test]
fn sshd_with_a_cover_is_a_usage_error() {
    let place = Place::new("sshd", &["relay-a.test"]);
    let mut args = place.cover(None);
    args.extend(["--sshd".to_string(), "127.0.0.1:22".to_string()]);
    let out = run(&place.s.0, &args);
    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--sshd goes not with --cover"), "{said}");
}

/// A single-name certificate is no cover of a second name that it does not
/// hold: the refusal names the certificate.
#[test]
fn a_cover_name_that_the_certificate_does_not_hold_is_refused() {
    let place = Place::new("not-held", &["relay-a.test"]);
    let mut args = place.cover(None);
    args.extend([
        "--cover-name".to_string(),
        "relay-a.test".to_string(),
        "--cover-name".to_string(),
        "b.test".to_string(),
    ]);
    let out = run(&place.s.0, &args);
    assert_eq!(out.status.code(), Some(78), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a name of the certificate"), "{out:?}");
}
