//! The second factor of `podssh serve` on the command line (T-115):
//! `--totp FILE` read at the start, which refuses a file that others may
//! read or that holds no secret (78); and `--totp-new FILE`, which makes a
//! secret and prints its path alone: no secret goes to a terminal, a log
//! or a command line.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use podssh_ssh::server::totp::Totp;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CANTCREAT;
use crate::relay_settings::Refusal;
use crate::serve::ServeArgs;

/// The secret of `--totp`, or None.
pub fn open(args: &ServeArgs) -> Result<Option<Arc<Totp>>, Refusal> {
    let Some(path) = args.totp.as_deref() else { return Ok(None) };
    let totp = Totp::open(Path::new(path)).map_err(|why| Refusal::config(format!("--totp {why}")))?;
    Ok(Some(Arc::new(totp)))
}

/// `podssh serve --totp-new FILE`: the path on `out`, 0; 73 when FILE
/// cannot be made (one that exists is never written over); 64 with a flag
/// of a server.
pub fn create(args: &ServeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = args.totp_new.as_deref() else { return EXIT_USAGE };
    if args.stdio || args.name.is_some() || args.totp.is_some() {
        let _ = writeln!(err, "podssh serve: --totp-new makes a secret and serves nothing: give it alone");
        return EXIT_USAGE;
    }
    match Totp::create_new(Path::new(path)) {
        Ok(()) => {
            let _ = writeln!(out, "{path}");
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh serve: --totp-new {why}");
            EX_CANTCREAT
        }
    }
}

// Unix's, as serve is: the modes are Unix's.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A scratch directory, removed when the test ends, also on a failure.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A secret made, its path alone printed, and never made twice; with a
    /// flag of a server it is a usage error; a missing --totp refuses (78).
    #[test]
    fn a_secret_is_made_once_and_only_its_path_is_said() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let scratch = Scratch(std::env::temp_dir().join(format!("podssh-serve-totp-{}-{nanos}", std::process::id())));
        let dir = scratch.0.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("totp");
        let shown = path.display().to_string();
        let args = ServeArgs { totp_new: Some(shown.clone()), ..ServeArgs::default() };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(create(&args, &mut out, &mut err), 0, "{}", String::from_utf8_lossy(&err));
        assert_eq!(String::from_utf8_lossy(&out), format!("{shown}\n"), "the path alone");
        assert_eq!(create(&args, &mut out, &mut err), EX_CANTCREAT);
        // Under a directory that is not there: that directory, no os error.
        let nodir = ServeArgs { totp_new: Some(dir.join("none/t").display().to_string()), ..ServeArgs::default() };
        err.clear();
        assert_eq!(create(&nodir, &mut out, &mut err), EX_CANTCREAT);
        let said = String::from_utf8_lossy(&err);
        assert!(said.ends_with("none does not exist\n") && !said.contains("os error"), "{said}");
        let served = ServeArgs { stdio: true, ..args.clone() };
        assert_eq!(create(&served, &mut out, &mut err), EXIT_USAGE);
        let reading = ServeArgs { totp: Some(shown), ..ServeArgs::default() };
        assert!(open(&reading).unwrap().is_some());
        let missing = ServeArgs { totp: Some(dir.join("none").display().to_string()), ..ServeArgs::default() };
        let refusal = open(&missing).expect_err("missing");
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG, "{}", refusal.message);
    }
}
