//! The secret of the GSRN road (T-707), and the refusal of a build without
//! the road. The road's two ends share one secret, from a private file
//! that `--gsr-secret-file` or `PODSSH_GSR_SECRET_FILE` names, never from
//! argv, a URL or a line: the relay of gsocket derives the meeting address
//! and the password of TLS with SRP from it, so whoever holds it reaches the
//! node's door. The file is read only as a regular file of this user that
//! nobody else can read, as ssh reads a key, and no word of a refusal holds
//! its text. In a build without the feature `gsr`, the flags are refused
//! with exit 70, and the variable alone is passed over in silence.

use std::fmt;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::relay_settings::Refusal;

/// The variable of the secret file, as `--gsr-secret-file`.
pub const SECRET_ENV: &str = "PODSSH_GSR_SECRET_FILE";

/// The words of a build without the road.
pub fn not_built(what: &str) -> String {
    format!(
        "{what}: the GSRN road is not in this build; build podssh with --features gsr \
         (cargo build -p podssh-cli --features gsr)"
    )
}

/// The shared secret, kept out of each line: its `Debug` names no byte, and
/// its memory is wiped when it drops.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// The text, for the road alone.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The secret of `text`, a file's contents: its first line, without its
/// line end, as gs-netcat -k reads a key file; one line of text, which no
/// other line follows. `at` names the file in the words, which never hold
/// its text.
pub fn parse(text: &str, at: &str) -> Result<Secret, Refusal> {
    let mut lines = text.split('\n').map(|line| line.strip_suffix('\r').unwrap_or(line));
    let first = lines.next().unwrap_or_default();
    if first.trim().is_empty() {
        return Err(Refusal::config(format!("{at}: the first line holds no secret")));
    }
    if lines.any(|line| !line.trim().is_empty()) {
        return Err(Refusal::config(format!("{at}: one line, the secret, and no other")));
    }
    if first.chars().any(char::is_control) {
        return Err(Refusal::config(format!("{at}: the secret holds a control character")));
    }
    Ok(Secret(Zeroizing::new(first.to_string())))
}

/// The secret of the private file `path`; `flag` names where the path came
/// from, for the words.
pub fn read(path: &str, flag: &str) -> Result<Secret, Refusal> {
    let at = format!("{flag} {path}");
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("{at}: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, &at)
}

/// The secret file that `podssh ssh --gsr-secret-file` named in this run.
static GIVEN: OnceLock<String> = OnceLock::new();

/// Where this run's secret file comes from: the flag, else the variable;
/// none when neither names one.
pub fn chosen(flag: Option<&str>) -> Option<(String, &'static str)> {
    let given = flag.map(str::to_string).or_else(|| GIVEN.get().cloned());
    match given {
        Some(path) => Some((path, "--gsr-secret-file")),
        None => std::env::var(SECRET_ENV).ok().filter(|v| !v.trim().is_empty()).map(|path| (path, SECRET_ENV)),
    }
}

/// The secret of this run, when one is named: a file that does not read is
/// refused (78), as the user asked for the road.
pub fn secret(flag: Option<&str>) -> Result<Option<Secret>, Refusal> {
    match chosen(flag) {
        Some((path, from)) => read(&path, from).map(Some),
        None => Ok(None),
    }
}

/// `podssh ssh --gsr-secret-file FILE`, before anything is resolved: 70 in
/// a build without the road; else the file is read now, so that a bad one
/// is said before anything connects (78), and kept for the race of
/// `node://NAME`. The code of a run that ends here.
pub fn ssh_flag(flag: Option<&str>, err: &mut dyn Write) -> Option<i32> {
    let path = flag?;
    if !cfg!(feature = "gsr") {
        let _ = writeln!(err, "podssh ssh: {}", not_built("--gsr-secret-file"));
        return Some(EXIT_NOT_IMPLEMENTED);
    }
    if let Err(refusal) = read(path, "--gsr-secret-file") {
        return Some(refusal.report("ssh", err));
    }
    let _ = GIVEN.set(path.to_string());
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: &str = "--gsr-secret-file s";

    #[test]
    fn the_secret_is_the_first_line_without_its_line_end() {
        for text in ["sesame\n", "sesame\r\n", "sesame", "sesame\n\n  \n"] {
            assert_eq!(parse(text, AT).expect(text).expose(), "sesame", "{text:?}");
        }
        assert_eq!(parse("open sesame\n", AT).expect("spaces").expose(), "open sesame");
    }

    #[test]
    fn a_file_that_does_not_hold_one_secret_is_refused_in_words_that_hold_none_of_it() {
        for text in ["", "\n", "   \n", "sesame\nmore-of-it\n", "ses\u{7}ame\n"] {
            let refusal = parse(text, AT).err().unwrap_or_else(|| panic!("{text:?} was taken"));
            assert_eq!(refusal.code, 78, "{}", refusal.message);
            assert!(refusal.message.starts_with(AT), "{}", refusal.message);
            for word in ["sesame", "more-of-it", "ses"] {
                assert!(!refusal.message.contains(word), "{}", refusal.message);
            }
        }
    }

    #[test]
    fn the_debug_of_a_secret_names_no_byte_of_it() {
        let secret = parse("sesame\n", AT).expect("a secret");
        assert_eq!(format!("{secret:?}"), "Secret(..)");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_others_can_read_is_refused_and_its_text_is_not_said() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("podssh-gsr-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("secret");
        std::fs::write(&path, "sesame-of-the-test\n").expect("the file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("its mode");
        let shown = path.display().to_string();
        let refusal = read(&shown, "--gsr-secret-file").expect_err("a file that others can read");
        assert_eq!(refusal.code, 78, "{}", refusal.message);
        assert!(!refusal.message.contains("sesame-of-the-test"), "{}", refusal.message);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("its mode");
        assert_eq!(read(&shown, "--gsr-secret-file").expect("a private file").expose(), "sesame-of-the-test");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
