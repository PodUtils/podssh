//! `podssh keygen -s` and `-L` (T-021): user and host certificates, signed
//! by a CA key, and printed. The validity, the options, the lines and the
//! messages are those of the `ssh-keygen` of OpenSSH for Windows 10.0p2
//! (measured on 2026-10-11); a failure exits 1, where OpenSSH exits 255,
//! and a usage error 64. As OpenSSH does, `FILE-cert.pub` replaces one that
//! is there: a certificate is public, and is made again at each renewal.

use std::io::Write;
use std::path::Path;

use podssh_ssh::cert::{self, Request};
use podssh_ssh::options::Agent;
use podssh_ssh::russh::keys::ssh_key::{Certificate, HashAlg};
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};
use crate::keygen_sign::{block_on, open_private, public_key};

/// The CA that signs: a private key, or the agent's key (`-U`).
enum Ca {
    Key(Box<PrivateKey>),
    Agent(PublicKey),
}

/// `-s CA -I ID [-n PRINCIPALS] [-V VALIDITY] [-z SERIAL] [-O OPTION]
/// [-h] [-U] FILE...`: each FILE, a public key, to `FILE-cert.pub`.
pub fn sign(args: &KeygenArgs, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write, why: &str| {
        let _ = writeln!(err, "podssh keygen: {why}");
        EXIT_USAGE
    };
    let Some(key_id) = args.identity.as_deref() else {
        return usage(err, "Must specify key id (-I) when certifying");
    };
    if args.files.is_empty() {
        return usage(err, "-s signs each FILE, a public key: give one");
    }
    let mut request = Request::new(key_id, args.host_certificate);
    if let Some(principals) = &args.namespace {
        request.principals = principals.split(',').filter(|p| !p.is_empty()).map(str::to_string).collect();
    }
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if let Some(spec) = &args.validity {
        match cert::validity(spec, now) {
            Ok((after, before)) => (request.valid_after, request.valid_before) = (after, before),
            Err(why) => return usage(err, &why),
        }
    }
    if let Some(text) = &args.serial {
        match cert::serial(text) {
            Ok(serial) => request.serial = serial,
            Err(why) => return usage(err, &why),
        }
    }
    for option in &args.options {
        if let Err(why) = request.option(option) {
            return usage(err, &why);
        }
    }
    let rsa_hash = match args.key_type.as_deref() {
        None | Some("rsa-sha2-512") => HashAlg::Sha512,
        Some("rsa-sha2-256") => HashAlg::Sha256,
        Some(other) => {
            return usage(
                err,
                &format!("-t {other}: with -s, -t names the signature of an RSA CA: rsa-sha2-256 or rsa-sha2-512"),
            )
        }
    };
    let ca_path = Path::new(args.signature_file.as_deref().unwrap_or_default());
    let ca = match ca(ca_path, args.agent_key) {
        Ok(ca) => ca,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    let mut code = 0;
    for file in &args.files {
        match certify_one(file, &ca, &request, rsa_hash) {
            Ok((target, certificate)) => {
                if !args.quiet {
                    let kind = if certificate.cert_type().is_host() { "host" } else { "user" };
                    let principals = args.namespace.as_deref().map(|p| format!(" for {p}")).unwrap_or_default();
                    let _ = writeln!(
                        err,
                        "Signed {kind} key {target}: id \"{key_id}\" serial {}{principals} valid {}",
                        certificate.serial(),
                        cert::format_validity(certificate.valid_after(), certificate.valid_before())
                    );
                }
            }
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                code = EXIT_FAILED;
            }
        }
    }
    code
}

/// The CA of `-s`: its private key, its passphrase asked; with `-U`, its
/// public key, for the agent that holds it.
fn ca(path: &Path, agent: bool) -> Result<Ca, String> {
    let shown = path.display();
    let text = podssh_ssh::key_text::text_of(path)?;
    if agent {
        return public_key(path, &text)
            .map(Ca::Agent)
            .ok_or_else(|| format!("{shown} holds no public key for the agent to sign with"));
    }
    open_private(path, &text).map(|key| Ca::Key(Box::new(key)))
}

/// FILE, a public key, certified and written to `FILE-cert.pub` (FILE
/// without `.pub`): the path and the certificate.
fn certify_one(file: &str, ca: &Ca, request: &Request, rsa_hash: HashAlg) -> Result<(String, Certificate), String> {
    let text = podssh_ssh::key_text::text_of(Path::new(file))?;
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or_default();
    let public = PublicKey::from_openssh(line).map_err(|_| format!("{file}: not a public key"))?;
    let certificate = match ca {
        Ca::Key(key) => cert::certify(key, &public, request, rsa_hash)?,
        Ca::Agent(ca) => block_on(cert::certify_with_agent(&Agent::FromEnvironment, ca, &public, request, rsa_hash))?,
    };
    let target = match file.strip_suffix(".pub") {
        Some(stem) => format!("{stem}-cert.pub"),
        None => format!("{file}-cert.pub"),
    };
    let line = certificate.to_openssh().map_err(|e| format!("could not encode the certificate: {e}"))?;
    // The error names the path, the step and the cause.
    replace(Path::new(&target), format!("{line}\n").as_bytes()).map_err(|e| podssh_ws::text::said(&e))?;
    Ok((target, certificate))
}

/// `bytes` in place of the file at `path`, whole: pod-core's atomic replace
/// (a temporary file beside it, synced, renamed, its directory synced). A
/// link at the path is replaced, not followed, as the rename did before. A
/// certificate that is there keeps its mode, as OpenSSH's truncate keeps
/// it; a new one is 0644, as `ssh-keygen -s` makes it: it is public.
fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use pod_core::files::Mode;
    let mode = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Mode::Keep,
        _ => Mode::Exact(0o644),
    };
    // A failed sync of the directory leaves the new file in place: no
    // failure, as the write before this one synced no directory either.
    pod_core::files::replace(path, bytes, mode).map(drop)
}

/// `-L -f FILE`: each certificate of FILE, as `ssh-keygen -L` prints it.
pub fn print(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -L prints the certificate in -f FILE");
        return EXIT_USAGE;
    };
    let text = match podssh_ssh::key_text::bytes_of(Path::new(path)) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    let mut any = false;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let certificate = match Certificate::from_openssh(line) {
            Ok(certificate) => certificate,
            Err(_) if PublicKey::from_openssh(line).is_ok() => {
                let _ = writeln!(err, "{path}:{number} is not a certificate");
                continue;
            }
            Err(e) => {
                let _ = writeln!(err, "{path}:{number}: invalid key: {e}");
                continue;
            }
        };
        any = true;
        if number == 1 {
            let _ = writeln!(out, "{path}:");
        } else {
            let _ = writeln!(out, "{path}:{number}:");
        }
        for line in cert::describe(&certificate) {
            let _ = writeln!(out, "{line}");
        }
    }
    if any {
        0
    } else {
        EXIT_FAILED
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("podssh-cert-{tag}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The modes of a certificate written in place: a new one is public, one
    /// that is there keeps what its owner set; nothing stays beside it.
    #[cfg(unix)]
    #[test]
    fn a_certificate_keeps_its_mode_and_a_new_one_is_public() {
        use std::os::unix::fs::PermissionsExt;
        for (before, after) in [(None, 0o644), (Some(0o600), 0o600), (Some(0o640), 0o640), (Some(0o644), 0o644)] {
            let dir = scratch("mode");
            let path = dir.join("user-cert.pub");
            if let Some(bits) = before {
                std::fs::write(&path, b"old\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits)).unwrap();
            }
            super::replace(&path, b"new\n").unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
            assert_eq!(mode(&path), after, "{before:?}");
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "a file was left beside it");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A link at the path is replaced, and what it named stays, as the
    /// rename of the write before this one did.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_certificate_is_replaced_not_followed() {
        let dir = scratch("link");
        let (target, link) = (dir.join("elsewhere"), dir.join("user-cert.pub"));
        std::fs::write(&target, b"theirs\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        super::replace(&link, b"new\n").unwrap();
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"theirs\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A directory that is missing is one error that names the path, and
    /// leaves nothing.
    #[test]
    fn a_missing_directory_is_an_error_that_names_the_path() {
        let dir = scratch("gone");
        let path = dir.join("missing").join("user-cert.pub");
        let e = super::replace(&path, b"new\n").unwrap_err();
        assert!(e.to_string().contains(&path.display().to_string()), "{e}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
