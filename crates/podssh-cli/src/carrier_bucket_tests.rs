//! The bucket's file (T-725): each name, the two forms of the keys, a name
//! that is no setting, a plain endpoint off the loopback, a short secret;
//! no refusal shows a word of a key or of the secret.

use super::*;

/// The made-up keys and secret of these tests: no service knows them.
const KEY_ID: &str = "PODSSHFILETEST";
const KEY_SECRET: &str = "podssh-file-test-secret-not-real";
const SECRET: &str = "a secret of the test, at least 16 bytes";

/// A directory with `FILE` (`settings`), `keys` and `secret` in it.
fn dir_with(tag: &str, settings: &str) -> (PathBuf, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("podssh-bucket-{tag}-{}-{nanos}-{seq}", std::process::id()));
    // Another test of this process may hold the umask window of a Unix
    // socket (mode 0600) while this directory is made. The window is
    // shared, and the mode is then set here whatever the process's mask.
    let window = crate::pipe::listen::UMASK_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    drop(window);
    let keys = format!("[default]\naws_access_key_id = {KEY_ID}\naws_secret_access_key = {KEY_SECRET}\n");
    std::fs::write(dir.join("keys"), keys).unwrap();
    std::fs::write(dir.join("secret"), format!("{SECRET}\n")).unwrap();
    let file = dir.join("bucket.conf");
    std::fs::write(&file, settings).unwrap();
    (dir, file.display().to_string())
}

const BASE: &str = "endpoint = https://s3.example.test\nbucket = links\nup = lab/up\ndown = lab/down\n";

fn refused(tag: &str, settings: &str) -> Refusal {
    let (dir, file) = dir_with(tag, settings);
    let refusal = read(&file).unwrap_err();
    let _ = std::fs::remove_dir_all(dir);
    assert!(!refusal.message.contains(KEY_SECRET) && !refusal.message.contains(SECRET), "{}", refusal.message);
    refusal
}

#[test]
fn a_file_with_one_key_pair_reads_with_its_paths_beside_it() {
    let (dir, file) = dir_with("one", &format!("# a comment\n{BASE}credentials = keys\nsecret-file = secret\n"));
    let spec = read(&file).expect("the file reads");
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(spec.place.endpoint.host, "s3.example.test");
    assert_eq!((spec.place.region.as_str(), spec.place.style), ("us-east-1", Style::Path));
    assert_eq!((spec.place.up.as_str(), spec.place.down.as_str()), ("lab/up", "lab/down"));
    assert_eq!(spec.keys.write.access_key, KEY_ID);
    assert_eq!(spec.keys.read.as_ref().map(|k| k.secret_key.as_str()), Some(KEY_SECRET));
    assert_eq!(&spec.secret[..], SECRET.as_bytes(), "the editor's newline is not the secret's");
    let alone = format!("{spec:?}");
    let shown = format!("{alone} {:?}", Found::Bucket(Arc::new(spec)));
    assert!(!shown.contains(KEY_SECRET) && !shown.contains(SECRET), "{shown}");
}

#[test]
fn two_key_pairs_or_a_public_read_prefix() {
    let two = format!("{BASE}write-credentials = keys\nread-credentials = keys\nsecret-file = secret\n");
    let (dir, file) = dir_with("two", &two);
    assert!(read(&file).unwrap().keys.read.is_some());
    let _ = std::fs::remove_dir_all(dir);
    let public = format!("{BASE}region = eu-west-1\nstyle = virtual\nwrite-credentials = keys\nread-credentials = none\nsecret-file = secret\n");
    let (dir, file) = dir_with("public", &public);
    let spec = read(&file).unwrap();
    let _ = std::fs::remove_dir_all(dir);
    assert!(spec.keys.read.is_none(), "an unsigned read");
    assert_eq!((spec.place.region.as_str(), spec.place.style), ("eu-west-1", Style::VirtualHost));
}

#[test]
fn each_fault_of_the_file_is_refused_with_78_and_shows_no_key() {
    let tail = "credentials = keys\nsecret-file = secret\n";
    let cases = [
        ("inline", format!("{BASE}{tail}aws_secret_access_key = {KEY_SECRET}\n"), "no name of a bucket's file"),
        (
            "plain",
            format!("endpoint = http://s3.example.test\nbucket = b1x\nup = u\ndown = d\n{tail}"),
            "loopback alone",
        ),
        ("same", format!("endpoint = https://h.test\nbucket = b1x\nup = a\ndown = a/b\n{tail}"), "two prefixes"),
        ("nokeys", format!("{BASE}secret-file = secret\n"), "give credentials"),
        ("both", format!("{BASE}{tail}write-credentials = keys\n"), "give credentials"),
        ("nosecret", format!("{BASE}credentials = keys\n"), "no secret-file"),
        ("twice", format!("{BASE}{tail}bucket = again\n"), "bucket is given twice (lines 2 and 7)"),
        ("style", format!("{BASE}{tail}style = sideways\n"), "path or virtual"),
        ("missing", format!("{BASE}credentials = elsewhere\nsecret-file = secret\n"), "the credentials"),
    ];
    for (tag, settings, words) in cases {
        let refusal = refused(tag, &settings);
        assert_eq!(refusal.code, 78, "{tag}: {}", refusal.message);
        assert!(refusal.message.starts_with("--carrier s3:"), "{tag}: {}", refusal.message);
        assert!(refusal.message.contains(words), "{tag}: {}", refusal.message);
    }
    let (dir, file) = dir_with("short", &format!("{BASE}credentials = keys\nsecret-file = secret\n"));
    std::fs::write(dir.join("secret"), "short").unwrap();
    let refusal = read(&file).unwrap_err();
    let _ = std::fs::remove_dir_all(dir);
    assert!(refusal.message.contains("at least 16"), "{}", refusal.message);
    assert_eq!(read("/nonexistent/podssh-bucket.conf").unwrap_err().code, 78);
}

#[test]
fn a_credentials_file_of_the_aws_form_and_its_faults() {
    let key =
        credentials_of("[default]\naws_access_key_id=ID\naws_secret_access_key = S\naws_session_token = T\n").unwrap();
    assert_eq!((key.access_key.as_str(), key.secret_key.as_str()), ("ID", "S"));
    assert_eq!(key.session_token.as_deref(), Some("T"));
    let first =
        credentials_of("[a]\naws_access_key_id=A\naws_secret_access_key=1\n[b]\naws_access_key_id=B\n").unwrap();
    assert_eq!(first.access_key, "A", "the first section");
    assert!(credentials_of("aws_access_key_id = ID\n").is_err());
    assert!(credentials_of("aws_access_key_id = I D\naws_secret_access_key = S\n").is_err());
    let why = credentials_of("just the secret\n").unwrap_err();
    assert!(!why.contains("secret\n") && !why.contains("just"), "{why}");
}

/// The shared reader of `NAME = VALUE` lines (the S3 FILE, its credentials
/// and the DNS FILE): one table of what each text gives.
#[test]
fn the_lines_of_a_file_from_one_table() {
    let line = |at: usize, name: &str, value: &str| Line { at, name: name.into(), value: value.into() };
    let cases: &[(&str, Result<Vec<Line>, &str>)] = &[
        ("a = 1\n# note\n; note\n\nB = two words\n", Ok(vec![line(1, "a", "1"), line(5, "b", "two words")])),
        ("\u{feff}a = 1\r\nb=\r\n", Ok(vec![line(1, "a", "1"), line(2, "b", "")])),
        ("[default]\na = 1\n[next]\nb = 2\n", Ok(vec![line(2, "a", "1")])),
        ("a = 1\nb = 2\nA = 3\n", Err("line 3: a is given twice (lines 1 and 3)")),
        ("a = 1\n= 2\n", Err("line 2: no name before =")),
        ("a = 1\njust words\n", Err("line 2: not NAME = VALUE")),
        ("a\0b = 1\na\0b = 2\n", Err("line 2: a\\u{0}b is given twice")),
    ];
    for (text, want) in cases {
        match (numbered(text), want) {
            (Ok(got), Ok(want)) => assert_eq!(&got, want, "{text:?}"),
            (Err(got), Err(want)) => assert!(got.contains(want), "{text:?}: {got}"),
            (got, _) => panic!("{text:?}: {got:?}"),
        }
    }
    assert_eq!(visible("a\u{202e}b\tc", 40), "a\\u{202e}b\\tc", "control and bidi bytes are shown escaped");
    assert_eq!(visible("abcdef", 3), "abc");
}

#[test]
fn a_bucket_is_a_carrier_and_its_terminal_rule_is_stdio_s_alone() {
    let (dir, file) = dir_with("found", &format!("{BASE}credentials = keys\nsecret-file = secret\n"));
    let found = crate::carrier::parse(&format!("s3:{file}")).expect("s3:FILE is a carrier");
    let again = crate::carrier::parse(&format!("s3:{file}")).unwrap();
    let _ = std::fs::remove_dir_all(dir);
    assert!(matches!(found, Found::Bucket(_)));
    assert_eq!(found, again, "one file, one carrier");
    assert!(crate::carrier::no_terminal(&found, true).is_ok(), "a bucket reads no terminal");
    assert!(crate::carrier::for_a_client(&format!("s3:{file}"), "its own").is_err(), "the file is gone");
}
