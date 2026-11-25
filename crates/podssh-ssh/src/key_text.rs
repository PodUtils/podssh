//! The bytes of a key, a certificate or a signature file, read within a
//! bound (T-966): `podssh keygen -l -f /dev/zero` read until the memory ran
//! out. No such file comes near 1 MiB: an RSA key of 16384 bits is under
//! 13 KiB, a certificate of many principals a few KiB. A `known_hosts` file
//! has its own bound, 16 MiB. And a library's error about such a file, in
//! podssh's words (T-974).

use std::io::{self, Read};
use std::path::Path;

use zeroize::Zeroizing;

/// The most bytes of a key, a certificate or a signature file.
pub const MOST: u64 = 1 << 20;

/// The bytes of `path`; a file past [`MOST`] is an error of the kind
/// `InvalidData` that says so, read no further.
pub fn read(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MOST + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MOST {
        let why = format!("it is larger than {} MiB, which no key, certificate or signature is", MOST >> 20);
        return Err(io::Error::new(io::ErrorKind::InvalidData, why));
    }
    Ok(bytes)
}

/// The text of `path`, as [`read`]; bytes that are not UTF-8 are refused,
/// as a key file is text.
pub fn read_text(path: &Path) -> io::Result<Zeroizing<String>> {
    let bytes = read(path)?;
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.to_string())),
        Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "it is not text, as a key file is")),
    }
}

/// [`read_text`], its failure as a line: `PATH: why`, with no `(os error N)`.
pub fn text_of(path: &Path) -> Result<Zeroizing<String>, String> {
    read_text(path).map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))
}

/// [`read`], its failure as [`text_of`] says it.
pub fn bytes_of(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    read(path).map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))
}

/// The words of a key library's error, by what it names: a key whose text
/// is cut said "Base64 decoding error: invalid length at 160", one whose
/// lengths are wrong "SshKey: length invalid". The library's own text stays
/// where no row knows it.
const WORDS: &[(&str, &str)] = &[
    ("Base64", "its base64 text is cut or damaged"),
    ("length invalid", "a length inside it is wrong: the file is cut or damaged"),
    ("did not contain valid UTF-8", "it is not text, as a key file is"),
    ("unexpected trailing data", "it has bytes after its end"),
    ("PEM", "its PEM armour is damaged"),
];

/// The names that russh puts before an error of the library under it.
const LIBRARIES: &[&str] = &["SshKey: ", "SshEncoding: ", "Der: ", "Spki: ", "Pkcs1: ", "Pkcs8: ", "Sec1: "];

/// A key library's error about a file, as a sentence of podssh's: a row's
/// words, else the error without the name of its library.
pub fn why(e: &dyn std::fmt::Display) -> String {
    let said = podssh_ws::text::said(e);
    if let Some((_, words)) = WORDS.iter().find(|(mark, _)| said.contains(mark)) {
        return (*words).to_string();
    }
    LIBRARIES.iter().find_map(|name| said.strip_prefix(name)).map_or_else(|| said.clone(), str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("podssh-key-text-{name}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Each file and what the reader makes of it: its text, or the words
    /// of its refusal.
    #[test]
    fn a_file_is_read_within_its_bound_and_as_text() {
        let most = MOST as usize;
        let cases: [(&str, Vec<u8>, Result<usize, &str>); 4] = [
            ("small", b"ssh-ed25519 AAAA k\n".to_vec(), Ok(19)),
            ("most", vec![b'a'; most], Ok(most)),
            ("past", vec![b'a'; most + 1], Err("larger than 1 MiB, which no key, certificate or signature is")),
            ("binary", vec![0xff, 0xfe, 0x00], Err("it is not text, as a key file is")),
        ];
        for (name, bytes, want) in cases {
            let path = scratch(name, &bytes);
            let got = text_of(&path).map(|text| text.len());
            let _ = std::fs::remove_file(&path);
            match (got, want) {
                (Ok(len), Ok(want)) => assert_eq!(len, want, "{name}"),
                (Err(why), Err(want)) => {
                    assert!(why.contains(want) && why.starts_with(&path.display().to_string()), "{name}: {why}")
                }
                (got, want) => panic!("{name}: {got:?}, not {want:?}"),
            }
        }
        let missing = text_of(Path::new("/nonexistent/podssh-key")).unwrap_err();
        assert!(!missing.contains("os error"), "{missing}");
    }

    /// The reader stops at the bound: a file with no end is refused, not
    /// read whole.
    #[cfg(unix)]
    #[test]
    fn a_file_with_no_end_is_refused_at_the_bound() {
        let why = text_of(Path::new("/dev/zero")).unwrap_err();
        assert!(why.contains("larger than 1 MiB"), "{why}");
    }

    #[test]
    fn a_library_s_error_is_said_in_podssh_s_words() {
        for (library, words) in [
            ("Base64 decoding error: invalid length at 160", "its base64 text is cut or damaged"),
            ("SshKey: length invalid", "a length inside it is wrong: the file is cut or damaged"),
            ("stream did not contain valid UTF-8", "it is not text, as a key file is"),
            ("an error of no row (os error 5)", "an error of no row"),
            ("Pkcs8: unknown scheme", "unknown scheme"),
            ("SshKey: algorithm unknown", "algorithm unknown"),
        ] {
            assert_eq!(why(&library), words, "{library}");
        }
    }
}
