//! With `PODSSH_OFFLINE`, a fault of the command line is still 64, and only
//! a command line that is right gets the refusal of the network, 69
//! (T-1020): `funnel` and `update` read their words first. One table.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `podssh ARGS` offline, in a home of its own: (code, stderr).
fn offline(args: &[&str]) -> (i32, String) {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let home = std::env::temp_dir().join(format!("podssh-offline-order-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_OFFLINE", "1").env("HOME", &home).env("USERPROFILE", &home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env_remove("PODSSH_OPENTUNNEL");
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
fn a_fault_of_the_command_line_is_64_offline_too() {
    let rows: [(&[&str], i32, &str); 6] = [
        (&["funnel", "--opentunnel", "--warp", "127.0.0.1:8080"], 64, "--warp"),
        (&["funnel", "127.0.0.1:99999"], 64, "\"99999\" is not a port"),
        (&["funnel", "nothost"], 64, "a funnel's TARGET is HOST:PORT"),
        (&["update", "--check", "--version", "bogus"], 64, "--version bogus"),
        // The controls: a right command line meets the refusal of the network.
        (&["funnel", "127.0.0.1:8080"], 69, "PODSSH_OFFLINE"),
        (&["update", "--check"], 69, "PODSSH_OFFLINE"),
    ];
    for (args, code, says) in rows {
        let (rc, err) = offline(args);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
}
