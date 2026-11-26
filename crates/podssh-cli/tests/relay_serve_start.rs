//! The start of `podssh relay serve` (T-1014): each file that it reads or
//! writes as it serves is checked before anything listens, and each line
//! names the file and the flag it is about; with `PODSSH_OFFLINE` it does
//! not start, in a listener's words. One table; nothing binds.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `podssh ARGS` with `vars`, in a home of its own: (code, stderr).
fn serve(args: &[&str], vars: &[(&str, &str)]) -> (i32, String) {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let home = std::env::temp_dir().join(format!("podssh-serve-start-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", &home).env("USERPROFILE", &home).env("XDG_CACHE_HOME", home.join("cache"));
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_OFFLINE", "PODSSH_LISTEN"] {
        cmd.env_remove(name);
    }
    cmd.envs(vars.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{args:?} did not end within 30 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    let _ = std::fs::remove_dir_all(&home);
    (status.code().unwrap_or(-1), err)
}

#[test]
fn a_file_that_the_role_cannot_use_stops_its_start_with_its_name() {
    let base = ["relay", "serve", "--listen", "127.0.0.1:0"];
    let with = |more: &[&'static str]| -> Vec<&'static str> { base.iter().chain(more).copied().collect() };
    let offline = [("PODSSH_OFFLINE", "1")];
    // (the arguments, the environment, the code, the words)
    type Row<'a> = (Vec<&'a str>, &'a [(&'a str, &'a str)], i32, &'a str);
    let rows: [Row; 4] = [
        (
            with(&["--cert", "c.pem", "--key", "k.pem", "--pairs", "/nonexistent/dir/p.json"]),
            &offline,
            78,
            "--pairs /nonexistent/dir/p.json: the directory /nonexistent/dir does not exist",
        ),
        (
            with(&["--cert", "/nonexistent/c.pem", "--key", "/nonexistent/k.pem"]),
            &[],
            78,
            "the certificate /nonexistent/c.pem: ",
        ),
        (with(&["--cert", "c.pem", "--key", "k.pem"]), &offline, 69, "a relay takes them and dials its targets"),
        (with(&["--cert", "c.pem", "--key", "k.pem", "--pairs", "/nonexistent/dir/p.json"]), &[], 78, "--pairs "),
    ];
    for (args, vars, code, says) in rows {
        let (rc, err) = serve(&args, vars);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert_eq!(err.lines().count(), 1, "one line: {err}");
        assert!(err.starts_with("podssh relay serve: "), "{err}");
    }
}
