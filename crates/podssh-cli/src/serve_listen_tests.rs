//! The addresses, the caps and the binds of `podssh serve --listen`
//! (T-124).

use std::path::PathBuf;

use super::*;

/// A private directory of the test, gone at its end.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let name = format!("podssh-serve-listen-{tag}-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let dir = std::env::temp_dir().join(name);
    podssh_relay::cache::private_dir(&dir).unwrap();
    Scratch(dir)
}

fn tcp(host: &str, port: u16) -> Address {
    Address::TcpListen { host: host.into(), port }
}

/// Each form of `--listen`, and each wrong one with the words that name
/// it: one table, as the parser's rule is one.
#[test]
fn each_listen_value_reads_or_is_refused_with_its_words() {
    let good = [
        ("2222", tcp("127.0.0.1", 2222)),
        ("0", tcp("127.0.0.1", 0)),
        ("localhost:22", tcp("127.0.0.1", 22)),
        ("0.0.0.0:443", tcp("0.0.0.0", 443)),
        ("[::1]:2222", tcp("::1", 2222)),
        ("unix:/run/user/1/serve.sock", Address::UnixListen("/run/user/1/serve.sock".into())),
    ];
    for (value, want) in good {
        assert_eq!(address(value).unwrap(), want, "{value}");
    }
    let bad = [
        ("", "PORT is a number"),
        ("x", "PORT is a number"),
        ("70000", "PORT is a number"),
        ("example.org:22", "no name is resolved"),
        ("::1:22", "in brackets"),
        ("[x]:22", "not an IPv6 address"),
        ("unix:", "names no socket"),
    ];
    for (value, words) in bad {
        let refusal = address(value).expect_err(value);
        assert_eq!(refusal.code, EX_USAGE, "{value}: {}", refusal.message);
        assert!(refusal.message.starts_with("--listen "), "{value}: {}", refusal.message);
        assert!(refusal.message.contains(words), "{value}: {}", refusal.message);
    }
    let long = format!("unix:/{}", "a".repeat(200));
    assert!(address(&long).expect_err("too long").message.contains("bytes"));
}

#[test]
fn a_cap_is_a_whole_number_in_its_bounds() {
    for (value, want) in [("1", Some(1)), ("64", Some(64)), (" 8 ", Some(8)), ("65536", Some(listen::CAP_MAX))] {
        assert_eq!(cap("--max-connections", value).ok(), want, "{value}");
    }
    for value in ["0", "-1", "65537", "many", ""] {
        let refusal = cap("--max-connections", value).expect_err(value);
        assert_eq!(refusal.code, EX_USAGE);
        assert!(refusal.message.contains("from 1 to 65536"), "{}", refusal.message);
    }
}

#[test]
fn a_plan_takes_each_address_once_and_its_caps() {
    let words = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
    assert_eq!(Plan::of(&[], None).unwrap(), None, "no --listen, no plan");
    // PODSSH_LISTEN=no would refuse here; a test does not set the
    // process's variables, so the plan is read with listening allowed.
    if pipe_listen::allowed().is_err() {
        return;
    }
    let plan = Plan::of(&words(&["2222", "unix:/tmp/s", "0", "0"]), Some("8")).unwrap().unwrap();
    assert_eq!(plan.listen.len(), 4, "port 0 twice is two ports");
    assert_eq!(plan.limits, Limits { connections: 8 });
    let twice = Plan::of(&words(&["2222", "127.0.0.1:2222"]), None).expect_err("the same address twice");
    assert!(twice.message.contains("given twice"), "{}", twice.message);
    assert_eq!(Plan::of(&words(&["1"]), None).unwrap().unwrap().limits.connections, listen::CONNECTIONS);
}

/// A refused bind names the address and the system's words; the host's
/// refusal (77) adds the ways with no listener, another failure (69) not.
#[test]
fn the_line_of_a_failed_bind_names_the_address_and_why() {
    let refused = cannot("127.0.0.1:22", "Permission denied (os error 13)", EX_NOPERM);
    assert_eq!(
        refused,
        "cannot listen on 127.0.0.1:22: Permission denied (os error 13); this host refuses the listener; --stdio and \
         podssh serve NAME need no listener"
    );
    let used = cannot("127.0.0.1:22", "Address in use", EX_UNAVAILABLE);
    assert!(!used.contains("refuses") && used.contains("Address in use"), "{used}");
}

/// The binds on this host, where they work: a port that the system
/// chooses and a socket of mode 0600, whose file goes with the listener;
/// a port that is taken ends the start with 69 and its address.
#[test]
fn each_listener_binds_and_a_taken_port_is_69() {
    let dir = scratch("bind");
    let socket = dir.0.join("s");
    let plan = Plan {
        listen: vec![tcp("127.0.0.1", 0), Address::UnixListen(socket.display().to_string())],
        limits: Limits::default(),
    };
    let bound = match Bound::all(&plan) {
        Ok(bound) => bound,
        // A host that refuses the bind (a sandbox) is the refusal's own test.
        Err((code, line)) if code == EX_NOPERM => {
            assert!(line.contains("this host refuses"), "{line}");
            return;
        }
        Err((code, line)) => panic!("{code}: {line}"),
    };
    let port = match &bound.listening[0] {
        Listening::Tcp(listener, _) => listener.local_addr().unwrap().port(),
        Listening::Unix(..) => panic!("the first is TCP"),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let meta = std::fs::metadata(&socket).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "the socket's mode");
    }
    let taken = Plan { listen: vec![tcp("127.0.0.1", port)], limits: Limits::default() };
    let (code, line) = Bound::all(&taken).err().expect("the port is taken");
    assert_eq!(code, EX_UNAVAILABLE, "{line}");
    assert!(line.starts_with(&format!("cannot listen on 127.0.0.1:{port}: ")), "{line}");
    drop(bound);
    assert!(!socket.exists(), "the socket's file goes with its listener");
}
