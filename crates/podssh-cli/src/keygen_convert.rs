//! `podssh keygen -e` and `-i` (T-022): a public key in the formats of other
//! systems, RFC 4716 (the default), PKCS#8 and PEM, as `ssh-keygen -e` and
//! `-i` convert them. `-i` imports public keys only: podssh never prints a
//! private key, and `-p` writes one in another format. Here too are the
//! reading of a key in each format, for `-y`, `-l` and `-e`, and the text
//! of a private key in the format of `-m`.

use std::io::Write;
use std::path::Path;

use podssh_ssh::convert::{self, Format};
use podssh_ssh::keygen::{self, KeyFile};
use podssh_ssh::prompt;
use podssh_ssh::russh::keys::ssh_key::LineEnding;
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};

/// `-e -f FILE [-m FORMAT]`: the public key of FILE (a public key, or the
/// half of a private key) in FORMAT, on stdout.
pub fn export(args: &KeygenArgs, format: Option<Format>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(file) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -e exports the key in -f FILE");
        return EXIT_USAGE;
    };
    let key = match load_key(Path::new(file), false) {
        Ok(KeyFile::Public(key)) => key,
        Ok(KeyFile::Private(key)) => key.public_key().clone(),
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    match convert::export(&key, format.unwrap_or(Format::Rfc4716), &crate::keygen::default_comment()) {
        Ok(text) => {
            let _ = out.write_all(text.as_bytes());
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

/// `-i -f FILE [-m FORMAT]`: the public key of FILE, in FORMAT, as a line of
/// OpenSSH on stdout.
pub fn import(args: &KeygenArgs, format: Option<Format>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(file) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -i imports the key in -f FILE");
        return EXIT_USAGE;
    };
    let text = match podssh_ssh::key_text::bytes_of(Path::new(file)) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    match convert::import(&text, format).and_then(|key| key.to_openssh().map_err(|e| e.to_string())) {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {file}: {why}");
            EXIT_FAILED
        }
    }
}

/// The text of a private key in the format of `-m` (T-022): PEM or PKCS#8
/// through `podssh_ssh::convert`; else, and for an Ed25519 key, which has no
/// other form, OpenSSH's, encrypted with `passphrase` unless it is empty.
pub(crate) fn private_text(
    key: &PrivateKey,
    format: Option<Format>,
    passphrase: &str,
    err: &mut dyn Write,
) -> Result<Zeroizing<String>, String> {
    if let Some(format) = format {
        if let Some(text) = convert::private_text(key, format, passphrase)? {
            return Ok(text);
        }
        if format != Format::Rfc4716 {
            let _ = writeln!(
                err,
                "podssh keygen: an {} key has no form of -m {}: it is written in the format of OpenSSH, as \
                 ssh-keygen writes it",
                podssh_ssh::known_hosts::key_type(key.public_key()),
                args_format_name(format)
            );
        }
    }
    keygen::protect(key.clone(), passphrase)?
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("could not encode the key: {e}"))
}

fn args_format_name(format: Format) -> &'static str {
    match format {
        Format::Rfc4716 => "RFC4716",
        Format::Pkcs8 => "PKCS8",
        Format::Pem => "PEM",
    }
}

/// The key of `path` for `-y` (`private`), `-l` and `-e`: a public key
/// line; for `-l` and `-e` also the public half of an OpenSSH private key,
/// encrypted or not, and `FILE.pub`; else the private key, in each format
/// that `podssh ssh -i` reads (T-022), its passphrase asked when it has one.
pub(crate) fn load_key(path: &Path, private: bool) -> Result<KeyFile, String> {
    let shown = path.display();
    // A key file of a TPM holds its public area in the clear (T-839).
    if podssh_ssh::tpm::is_key_file(path) {
        let file = podssh_ssh::tpm::read_key_file(path)?;
        return podssh_ssh::tpm::public_key(&file).map(KeyFile::Public);
    }
    let text = podssh_ssh::key_text::text_of(path)?;
    if let Some(public) = crate::keygen_sign::public_line(&text) {
        if private {
            return Err(format!("{shown} holds a public key; -y reads a private key"));
        }
        return Ok(KeyFile::Public(public));
    }
    if !private {
        let beside = podssh_ssh::key_text::read_text(&keygen::public_path(path)).ok();
        let beside = beside.as_deref().and_then(|text| crate::keygen_sign::public_line(text));
        if let Ok(key) = PrivateKey::from_openssh(text.trim_start()) {
            return Ok(KeyFile::Public(half_or_beside(key.public_key(), beside)));
        }
        if let Some(public) = beside {
            return Ok(KeyFile::Public(public));
        }
    }
    match podssh_ssh::key_file::decode(&text, None) {
        Ok(key) => Ok(KeyFile::Private(key)),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {
            let passphrase = prompt::ask("Enter passphrase: ", false)
                .map_err(|e| format!("{shown} is encrypted, and its passphrase: {}", podssh_ws::text::said(&e)))?;
            podssh_ssh::key_file::decode(&text, Some(passphrase.as_str()))
                .map(KeyFile::Private)
                .map_err(|_| format!("{shown}: incorrect passphrase"))
        }
        // podssh's own key file (client.key, node.key): the 64 hex digits of
        // an Ed25519 seed, so that -y prints the line that --grant-to and an
        // allowlist take (T-828).
        Err(_) if seed_of(&text).is_some() => {
            let seed = seed_of(&text).unwrap_or_default();
            let pair = podssh_ssh::russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
            Ok(KeyFile::Private(PrivateKey::from(pair)))
        }
        Err(e) => Err(format!("{shown}: not a key that podssh reads: {}", podssh_ssh::key_text::why(&e))),
    }
}

/// The public half of a private key, or `FILE.pub` beside it when that is
/// the same key: an encrypted key keeps its comment in the encrypted part,
/// so `ssh-keygen -l` reads it from `FILE.pub` first (T-868). A `FILE.pub`
/// of another key is not this key, and its comment would not be true.
fn half_or_beside(half: &PublicKey, beside: Option<PublicKey>) -> PublicKey {
    match beside {
        Some(public) if public.key_data() == half.key_data() => public,
        _ => half.clone(),
    }
}

/// The seed of podssh's own key file: one line of 64 hex digits.
fn seed_of(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let word = text.trim();
    if word.len() != 64 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&word[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// podssh's own key file is read as the key that its identity is: the
    /// same public half, which `-y` prints for `--grant-to` (T-828); a line
    /// of another length or of a letter past f is none.
    #[test]
    fn podssh_s_own_key_file_is_its_identity_s_key() {
        let hex = "71e2bb6174508077004f6626e4c46d42042c889876136a41aa55aa55aa55aa55";
        let seed = seed_of(&format!("{hex}\n")).expect("a seed");
        let pair = podssh_ssh::russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let identity = podssh_relay::identity::Identity::from_seed(&seed);
        assert_eq!(pair.public.0, identity.public().0);
        assert!(seed_of(&hex[..62]).is_none());
        assert!(seed_of(&hex.replace('7', "g")).is_none());
    }

    /// `-l` on a private key: the comment of `FILE.pub` when it is the same
    /// key, encrypted or not; the key's own half when `FILE.pub` is missing
    /// or holds another key (T-868). One table, one rule.
    #[test]
    fn the_comment_of_l_comes_from_file_pub_when_it_is_the_same_key() {
        use podssh_ssh::keygen::{generate, protect, KeyKind};
        let dir = std::env::temp_dir().join(format!("podssh-l-comment-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = generate(KeyKind::Ed25519, "me@lab").unwrap();
        let other = generate(KeyKind::Ed25519, "someone@else").unwrap();
        let line = |k: &PrivateKey| k.public_key().to_openssh().unwrap();
        let locked = protect(key.clone(), "right").unwrap();
        let text = |k: &PrivateKey| k.to_openssh(LineEnding::LF).unwrap().to_string();
        // (private key text, FILE.pub text or none, the comment shown)
        let rows: Vec<(String, Option<String>, &str)> = vec![
            (text(&locked), Some(line(&key)), "me@lab"),
            (text(&locked), None, ""),
            (text(&locked), Some(line(&other)), ""),
            (text(&key), Some(line(&key)), "me@lab"),
            (text(&key), None, "me@lab"),
            (text(&key), Some(line(&other)), "me@lab"),
        ];
        for (i, (private, public, comment)) in rows.into_iter().enumerate() {
            let path = dir.join(format!("key{i}"));
            std::fs::write(&path, private).unwrap();
            if let Some(public) = public {
                std::fs::write(keygen::public_path(&path), public).unwrap();
            }
            let Ok(KeyFile::Public(shown)) = load_key(&path, false) else { panic!("row {i}: no public key") };
            assert_eq!(shown.key_data(), key.public_key().key_data(), "row {i}: the key");
            assert_eq!(shown.comment().as_str_lossy(), comment, "row {i}: the comment");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
