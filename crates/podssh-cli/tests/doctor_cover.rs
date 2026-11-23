//! `podssh doctor --cover NAME` against a local cover relay (#225, T-766):
//! the delegated credential is requested with a token, checked against the
//! chain, the name, the window and the TLS exporter, and the same verifier
//! is shown to refuse another issuer, a lapsed window and another exporter,
//! each by name. The test is the role and the doctor as processes, on the
//! loopback, with a certificate of the test's CA.

#![cfg(unix)]

mod serve_certs;

use std::process::{Command, Stdio};
use std::time::Duration;

use serve_certs::{ca_and_leaf, podssh, replace, until, Killed, Scratch};

const NAME: &str = "relay-a.test";

/// `podssh ARGS` in `dir`, with no steering variable of this machine.
fn run(dir: &std::path::Path, args: &[String]) -> std::process::Output {
    let mut cmd: Command = podssh(dir);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.env_remove("PODSSH_OFFLINE").env_remove("PODSSH_CACHE_DIR").env("PODSSH_CACHE_DIR", dir.join("cache"));
    let mut child = cmd.spawn().expect("the podssh binary runs");
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} still ran after 120 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn doctor_checks_the_delegated_credential_and_names_each_refusal() {
    let s = Scratch(std::env::temp_dir().join(format!(
        "podssh-doctor-cover-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )));
    std::fs::create_dir_all(s.0.join("cache")).unwrap();
    std::fs::create_dir_all(s.0.join("site")).unwrap();
    std::fs::write(s.0.join("site/index.html"), b"<html><body>cover</body></html>").unwrap();
    let (ca, leaf, key) = ca_and_leaf("doctor-cover");
    let (ca_file, cert, key_file) = (s.0.join("ca.pem"), s.0.join("cert.pem"), s.0.join("key.pem"));
    std::fs::write(&ca_file, ca).unwrap();
    replace(&cert, &leaf);
    replace(&key_file, &key);
    let (log, port_file) = (s.0.join("role.log"), s.0.join("port"));
    let socket = s.0.join("control.sock");
    let role = podssh(&s.0)
        .args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--allow-private"])
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key_file)
        .arg("--cover")
        .arg(s.0.join("site"))
        .arg("--control-socket")
        .arg(&socket)
        .arg("--port-file")
        .arg(&port_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let _role = Killed(role);
    let mut port = 0;
    until("the role's port", &log, || {
        port = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
        port != 0
    });

    let args: Vec<String> = [
        "doctor".to_string(),
        "--quick".to_string(),
        "--cover".to_string(),
        NAME.to_string(),
        "--relay-host".to_string(),
        format!("{NAME}:{port}"),
        "--relay-addr".to_string(),
        format!("{NAME}=127.0.0.1"),
        "--ca-file".to_string(),
        ca_file.display().to_string(),
    ]
    .to_vec();
    let out = run(&s.0, &args);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let line = |label: &str| {
        text.lines()
            .find(|line| {
                line.starts_with("  ")
                    && line
                        .get(8..)
                        .is_some_and(|head| head.starts_with(label) && head.as_bytes().get(label.len()) == Some(&b' '))
            })
            .unwrap_or_else(|| panic!("no line {label}:\n{text}"))
            .to_string()
    };
    let credential = line("cover credential");
    assert!(credential.starts_with("  ok"), "{credential}\n{text}");
    assert!(credential.contains(&format!("issued by {NAME} for {NAME}")), "{credential}");
    assert!(credential.contains("bound to this TLS exporter"), "{credential}");
    assert!(credential.contains("subject "), "{credential}");

    let issuer = line("cover issuer");
    assert!(issuer.starts_with("  ok") && issuer.contains("another name"), "{issuer}");
    let window = line("cover window");
    assert!(window.starts_with("  ok") && window.contains("expired"), "{window}");
    let exporter = line("cover exporter");
    assert!(exporter.starts_with("  ok") && exporter.contains("bound to another exporter"), "{exporter}");
    // The report holds no token: the line says it was minted, not what it is.
    assert!(!text.contains("X-Relay-Token"), "{text}");
}
