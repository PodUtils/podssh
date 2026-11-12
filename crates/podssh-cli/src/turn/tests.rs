//! The settings of `--turn`: the flag before the variable, a credential
//! file that is required and private, and no credential in the URI.

use super::*;

fn flags(url: Option<&str>, file: Option<&str>) -> Flags {
    Flags { url: url.map(String::from), auth_file: file.map(String::from) }
}

/// A private file of `text`, removed when the test ends.
struct Private(std::path::PathBuf);

impl Private {
    fn new(name: &str, text: &str) -> Private {
        let dir = std::env::temp_dir().join(format!("podssh-turn-cli-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("auth");
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Private(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

#[test]
fn the_flag_wins_and_its_file_gives_the_credential() {
    let file = Private::new("wins", "alice:s3cret\n");
    let road = from(
        &flags(Some("turns:t.example.org"), Some(file.path())),
        Some("turns:o.example".into()),
        None,
        Trust::Default,
    )
    .unwrap()
    .unwrap();
    assert_eq!(road.shown(), "turns:t.example.org");
    assert!(!format!("{road:?}").contains("s3cret"));
    let env = from(&flags(None, None), Some("turns:o.example:5349".into()), Some(file.path().into()), Trust::Default)
        .unwrap()
        .unwrap();
    assert_eq!(env.shown(), "turns:o.example:5349");
    assert_eq!(from(&flags(None, None), None, None, Trust::Default).unwrap(), None);
}

#[test]
fn a_server_with_no_file_a_file_with_no_server_and_a_bad_uri_are_refused() {
    let none = from(&flags(Some("turns:t.example"), None), None, None, Trust::Default).unwrap_err();
    assert!(none.message.contains("--turn-auth-file FILE"), "{}", none.message);
    let alone = from(&flags(None, Some("/nonexistent/podssh-turn")), None, None, Trust::Default).unwrap_err();
    assert!(alone.message.starts_with("--turn-auth-file is for --turn"), "{}", alone.message);
    let plain = from(&flags(Some("turn:t.example"), None), None, None, Trust::Default).unwrap_err();
    assert!(plain.message.starts_with("--turn: turn:t.example has no TLS"), "{}", plain.message);
    let user = from(&flags(Some("turns:a:b@t.example"), None), None, None, Trust::Default).unwrap_err();
    assert!(user.message.contains("holds no credential"), "{}", user.message);
    let var = from(&flags(None, None), Some("https://t.example".into()), None, Trust::Default).unwrap_err();
    assert!(var.message.starts_with("PODSSH_TURN: "), "{}", var.message);
}

#[test]
fn a_file_that_does_not_read_is_named_by_its_line_never_its_text() {
    let file = Private::new("bad", "\nno-colon-s3cret\n");
    let bad = from(&flags(Some("turns:t.example"), Some(file.path())), None, None, Trust::Default).unwrap_err();
    assert!(bad.message.contains("line 2:") && !bad.message.contains("s3cret"), "{}", bad.message);
}
