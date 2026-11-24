//! The words of the third black-box pass (T-868), offline: each line that
//! the pass found not true or not clear, against the binary. One table, one
//! rule: each row's code, the words its stderr names, and the words it must
//! not hold. `podssh help VERB` is `VERB --help`, byte for byte.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The bound on each run: nothing here connects.
const LIMIT: Duration = Duration::from_secs(30);

/// A policy file that loads: the refusals of `--policy` come after it is read.
const POLICY: &str = "# One key exchange.\nname = \"curve25519 only\"\nversion = 1\n\
key exchanges = curve25519-sha256\n";

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-words-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    dir
}

/// `podssh ARGS` with HOME and the cache in `home`, no settings, no
/// ssh_config and no network, within [`LIMIT`].
fn podssh(home: &Path, args: &[&str]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", home).env("USERPROFILE", home).env("PODSSH_CACHE_DIR", home.join("cache"));
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("PODSSH_OFFLINE", "1");
    for name in ["PODSSH_RELAY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PAGER"] {
        cmd.env_remove(name);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ran { code: status.code(), out: out.join().unwrap(), err: err.join().unwrap() }
}

#[test]
fn each_line_of_the_pass_is_true_and_clear() {
    let home = scratch("lines");
    let policy = home.join("policy.txt");
    std::fs::write(&policy, POLICY).unwrap();
    let policy = policy.to_str().unwrap();
    // (the words, the code, what stderr names, what it must not hold)
    // (arguments, exit code, words stderr holds, words it never holds)
    type Row<'a> = (Vec<&'a str>, i32, Vec<&'a str>, Vec<&'a str>);
    let rows: Vec<Row> = vec![
        // A far name gets no suggestion, and no -o where none was given.
        (
            vec!["ssh", "--bogus-flag", "host"],
            64,
            vec!["'--bogus-flag'", "podssh ssh --help"],
            vec!["Did you mean", "-o"],
        ),
        (vec!["ssh", "--relay-hots", "r.example", "host"], 64, vec!["Did you mean '--relay-host'"], vec!["-o"]),
        (vec!["ssh", "-o", "BatchMode=yes", "--bogus-flag", "host"], 64, vec!["no -o setting was dropped"], vec![]),
        // The refusals of --policy beside another flag say what to do.
        (
            vec!["ssh", "--policy", policy, "--persist", "host"],
            64,
            vec!["--policy and --persist cannot be used together"],
            vec!["give one"],
        ),
        (
            vec!["ssh", "--policy", policy, "--upgrade", "host"],
            64,
            vec!["--policy and --upgrade cannot be used together"],
            vec!["give one"],
        ),
        (
            vec!["ssh", "--upgrade", "--persist", "host"],
            64,
            vec!["--upgrade and --persist cannot be used together"],
            vec!["give one"],
        ),
        (
            vec!["health", "--policy", policy, "--preflight", "host"],
            64,
            vec!["--policy and --preflight cannot be used together"],
            vec!["give one"],
        ),
        // `help WORD` that names no verb is refused as that word, not as `help`.
        (vec!["help", "nosuchverb"], 64, vec!["unknown subcommand 'nosuchverb'"], vec!["'help'"]),
        // A name that never ran did not end.
        (vec!["detached", "stop", "never-was"], 69, vec!["never-was"], vec!["ended"]),
    ];
    for (args, code, names, lacks) in rows {
        let ran = podssh(&home, &args);
        assert_eq!(ran.code, Some(code), "{args:?}: {}", ran.err);
        for text in names {
            assert!(ran.err.contains(text), "{args:?} lacks {text:?}: {}", ran.err);
        }
        for text in lacks {
            assert!(!ran.err.contains(text), "{args:?} holds {text:?}: {}", ran.err);
        }
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// `podssh help VERB` prints what `podssh VERB --help` prints, and `podssh
/// help` what `podssh --help` prints (T-868).
#[test]
fn help_verb_is_verb_help() {
    let home = scratch("help");
    for (said, same) in [
        (vec!["help", "ssh"], vec!["ssh", "--help"]),
        (vec!["help", "health"], vec!["health", "--help"]),
        (vec!["help"], vec!["--help"]),
    ] {
        let (a, b) = (podssh(&home, &said), podssh(&home, &same));
        assert_eq!(a.code, Some(0), "{said:?}: {}", a.err);
        assert_eq!((a.code, &a.out), (b.code, &b.out), "{said:?} and {same:?}");
        assert!(!a.out.is_empty(), "{said:?}: no help");
    }
    let _ = std::fs::remove_dir_all(&home);
}
