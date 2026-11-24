//! `podssh keygen -t ecdsa-tpm` (T-839): an ECDSA P-256 key that the TPM
//! makes and keeps, sealed to the PCRs of `-O pcr=LIST` (PCR 7, the state
//! of Secure Boot, by default). Its file is a `TSS2 PRIVATE KEY` that only
//! this TPM can load, and the TPM signs with it only while those PCRs hold
//! the values that they hold now. The probe runs before anything else:
//! with no TPM that podssh may reach, it says why and writes nothing (69).
//!
//! The key has no passphrase: the TPM takes no password for it, only its
//! policy, so `-N` is not asked. The file is private all the same, as its
//! policy names what the key is sealed to.

use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_ssh::tpm::{self, Pcrs};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::keygen::{tell_saved, KeygenArgs, EXIT_FAILED, KEY_FILES};

/// What `-O` asks of a new key sealed to a TPM.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    pcrs: Pcrs,
    device: Option<PathBuf>,
}

fn options(list: &[String]) -> Result<Options, String> {
    let mut options = Options { pcrs: Pcrs::parse(tpm::DEFAULT_PCRS)?, device: None };
    for option in list {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (option.as_str(), None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("pcr" | "pcrs", Some(list)) => options.pcrs = Pcrs::parse(list).map_err(|e| format!("-O {option}: {e}"))?,
            ("device", Some(path)) if !path.is_empty() => options.device = Some(PathBuf::from(path)),
            _ => {
                return Err(format!(
                    "-O {option}: a new key sealed to a TPM takes pcr=LIST (numbers of 0 to 23, such as 0,7) and device=PATH"
                ))
            }
        }
    }
    Ok(options)
}

/// Make the key in the TPM, and write its file to `path` (which does not
/// exist) and `path.pub`.
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
    // The probe: with no TPM, nothing is made and nothing is written.
    let device = match tpm::probe(options.device.as_deref()) {
        Ok(device) => device,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EX_UNAVAILABLE;
        }
    };
    if !args.quiet {
        let _ = writeln!(out, "Generating public/private ecdsa-tpm key pair in {}.", device.describe());
        let _ = writeln!(out, "Sealed to the PCRs {} of the SHA-256 bank, as they are now.", options.pcrs.text());
    }
    let written = tpm::make(&device, options.pcrs, comment).and_then(|(file, public)| {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn given(list: &[&str]) -> Result<Options, String> {
        options(&list.iter().map(|o| o.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_options_of_a_sealed_key_are_read() {
        assert_eq!(given(&[]).unwrap(), Options { pcrs: Pcrs::parse("7").unwrap(), device: None });
        let all = given(&["pcr=0,7,11", "device=/dev/tpmrm1"]).unwrap();
        assert_eq!(all.pcrs.numbers(), vec![0, 7, 11]);
        assert_eq!(all.device, Some(PathBuf::from("/dev/tpmrm1")));
        for bad in ["pcr=", "pcr=24", "pcr", "device=", "resident", "application=ssh:x"] {
            assert!(given(&[bad]).is_err(), "{bad}");
        }
    }
}
