//! `podssh keygen -t ecdsa-tpm` (T-839): an ECDSA P-256 key that the TPM
//! makes and keeps, sealed to the PCRs of `-O pcr=LIST` (PCR 7, the state
//! of Secure Boot, by default). Its file is a `TSS2 PRIVATE KEY` that only
//! this TPM can load, and the TPM signs with it only while those PCRs hold
//! the values that they hold now. The probe runs before anything else:
//! with no TPM that podssh may reach, it says why and writes nothing (69).
//!
//! With `-O policy-key=FILE`, the key takes each boot state that the ECDSA
//! P-256 key of FILE signs, and the file holds the first, the state of now.
//! After a firmware's update, `-O add-policy` with the same policy key
//! signs the new state into the key file of `-f`, and the key signs again
//! (the offline update): the policy key is kept off the host.
//!
//! The key has no passphrase: the TPM takes no password for it, only its
//! policy, so `-N` is not asked. The file is private all the same, as its
//! policy names what the key is sealed to.

use std::io::Write;
use std::path::{Path, PathBuf};

use pod_core::files::{Mode, Replace};
use podssh_ssh::tpm::{self, KeyFile, Pcrs, PolicyKey};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::keygen::{tell_saved, KeygenArgs, EXIT_FAILED, KEY_FILES};

/// What `-O` asks of a key sealed to a TPM.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    pcrs: Pcrs,
    /// `pcr=` was given; else `add-policy` takes the PCRs of the file.
    pcrs_given: bool,
    device: Option<PathBuf>,
    policy_key: Option<PathBuf>,
    add_policy: bool,
}

fn options(list: &[String]) -> Result<Options, String> {
    let mut options = Options {
        pcrs: Pcrs::parse(tpm::DEFAULT_PCRS)?,
        pcrs_given: false,
        device: None,
        policy_key: None,
        add_policy: false,
    };
    for option in list {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (option.as_str(), None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("pcr" | "pcrs", Some(list)) => {
                options.pcrs = Pcrs::parse(list).map_err(|e| format!("-O {option}: {e}"))?;
                options.pcrs_given = true;
            }
            ("device", Some(path)) if !path.is_empty() => options.device = Some(PathBuf::from(path)),
            ("policy-key", Some(path)) if !path.is_empty() => options.policy_key = Some(PathBuf::from(path)),
            ("add-policy", None) => options.add_policy = true,
            _ => {
                return Err(format!(
                    "-O {option}: a key sealed to a TPM takes pcr=LIST (numbers of 0 to 23, such as 0,7), device=PATH, \
                     policy-key=FILE and add-policy"
                ))
            }
        }
    }
    if options.add_policy && options.policy_key.is_none() {
        return Err("-O add-policy signs with the policy key: give -O policy-key=FILE too".into());
    }
    Ok(options)
}

/// Make the key in the TPM, and write its file to `path` (which does not
/// exist) and `path.pub`; or, with `-O add-policy`, sign the boot state of
/// now into the key file at `path`.
pub(crate) fn make(args: &KeygenArgs, path: &Path, comment: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let options = match options(&args.options) {
        Ok(options) => options,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_USAGE;
        }
    };
    if args.format.is_some() {
        let _ = writeln!(err, "podssh keygen: -m: a key sealed to a TPM has the format TSS2 PRIVATE KEY only");
        return EXIT_USAGE;
    }
    if options.add_policy {
        return add_policy(args, &options, path, out, err);
    }
    // The probe: with no TPM, nothing is made and nothing is written.
    let device = match tpm::probe(options.device.as_deref()) {
        Ok(device) => device,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EX_UNAVAILABLE;
        }
    };
    let policy_key = match options.policy_key.as_deref().map(open_policy_key).transpose() {
        Ok(key) => key,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    if !args.quiet {
        let _ = writeln!(out, "Generating public/private ecdsa-tpm key pair in {}.", device.describe());
        let pcrs = options.pcrs.text();
        let _ = match &options.policy_key {
            None => writeln!(out, "Sealed to the PCRs {pcrs} of the SHA-256 bank, as they are now."),
            Some(file) => {
                let file = file.display();
                writeln!(out, "Sealed to the boot states that {file} signs; first the PCRs {pcrs} as they are now.")
            }
        };
    }
    let written = tpm::make_with(&device, options.pcrs, comment, policy_key.as_ref()).and_then(|(file, public)| {
        let key = public.to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;
        let line = if comment.is_empty() { key } else { format!("{key} {comment}") };
        let public_path = podssh_ssh::keygen::write_texts(path, &file.to_pem(), &line, KEY_FILES)?;
        Ok((public, public_path))
    });
    match written {
        Ok((public, public_path)) => {
            if !args.quiet {
                tell_saved(out, path, &public_path, &public, comment);
            }
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

/// The policy key of `-O policy-key=FILE`, its passphrase asked when it
/// has one.
fn open_policy_key(path: &Path) -> Result<PolicyKey, String> {
    let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let key = crate::keygen_sign::open_private(path, &text)?;
    PolicyKey::new(key).map_err(|e| format!("{}: {e}", path.display()))
}

/// `-O add-policy`: the boot state of now, signed by the policy key, put
/// first among the signed policies of the key file at `path`, which is
/// replaced whole or not at all. The key itself does not change.
fn add_policy(args: &KeygenArgs, options: &Options, path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if !tpm::is_key_file(path) {
        let why = format!("{}: no key file of a TPM; -O add-policy changes the key file of -f", path.display());
        return failed(err, why);
    }
    let file = match tpm::read_key_file(path) {
        Ok(file) => file,
        Err(why) => return failed(err, why),
    };
    let device = match tpm::probe(options.device.as_deref()) {
        Ok(device) => device,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EX_UNAVAILABLE;
        }
    };
    let Some(key_path) = options.policy_key.as_deref() else { return EXIT_USAGE };
    let key = match open_policy_key(key_path) {
        Ok(key) => key,
        Err(why) => return failed(err, why),
    };
    let pcrs = options.pcrs_given.then_some(options.pcrs);
    let new = match tpm::add_policy(&device, &file, pcrs, &key, args.comment.clone()) {
        Ok(new) => new,
        Err(why) => return failed(err, format!("{}: {why}", path.display())),
    };
    if let Err(why) = replace(path, &new) {
        return failed(err, why);
    }
    if !args.quiet {
        let pcrs = tpm::signed_pcrs(&new).map(|p| p.text()).unwrap_or_default();
        let shown = path.display();
        let _ = writeln!(out, "Signed the boot state of the PCRs {pcrs} for {shown}, and the key signs in it.");
        let _ = writeln!(out, "The file holds {} signed policies; the newest is tried first.", new.auth_policies.len());
    }
    0
}

/// Say why in one line, and exit 1.
fn failed(err: &mut dyn Write, why: String) -> i32 {
    let _ = writeln!(err, "podssh keygen: {why}");
    EXIT_FAILED
}

/// Put `new` in place of the key file at `path`, whole or not at all:
/// pod-core's atomic replace, whose private temporary file is read back
/// and compared before the rename.
fn replace(path: &Path, new: &KeyFile) -> Result<(), String> {
    let check = |written: &Path| {
        let read = tpm::read_key_file(written).map_err(std::io::Error::other)?;
        if &read != new {
            return Err(std::io::Error::other("the new file reads otherwise than it was written"));
        }
        Ok(())
    };
    Replace::new(Mode::Private)
        .write_checked(path, new.to_pem().as_bytes(), check)
        .map(drop)
        .map_err(|e| format!("{} is unchanged: {e}", path.display()))
}

/// Whether `-O` asks to add a signed policy to an existing key file: then
/// the file of `-f` exists, where a new key never replaces one.
pub(crate) fn adds_policy(kind: podssh_ssh::keygen::KeyKind, options: &[String]) -> bool {
    kind == podssh_ssh::keygen::KeyKind::Tpm && options.iter().any(|o| o.eq_ignore_ascii_case("add-policy"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(list: &[&str]) -> Result<Options, String> {
        options(&list.iter().map(|o| o.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_options_of_a_sealed_key_are_read() {
        let none = given(&[]).unwrap();
        assert_eq!((none.pcrs, none.pcrs_given, &none.device), (Pcrs::parse("7").unwrap(), false, &None));
        assert!(none.policy_key.is_none() && !none.add_policy);
        let all = given(&["pcr=0,7,11", "device=/dev/tpmrm1", "policy-key=/media/key", "add-policy"]).unwrap();
        assert_eq!(all.pcrs.numbers(), vec![0, 7, 11]);
        assert!(all.pcrs_given && all.add_policy);
        assert_eq!(all.device, Some(PathBuf::from("/dev/tpmrm1")));
        assert_eq!(all.policy_key, Some(PathBuf::from("/media/key")));
        for bad in ["pcr=", "pcr=24", "pcr", "device=", "resident", "application=ssh:x", "policy-key=", "add-policy"] {
            assert!(given(&[bad]).is_err(), "{bad}");
        }
        assert!(adds_policy(podssh_ssh::keygen::KeyKind::Tpm, &["add-policy".into()]));
        assert!(!adds_policy(podssh_ssh::keygen::KeyKind::Ed25519, &["add-policy".into()]));
    }
}
