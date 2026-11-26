//! A second factor for `podssh serve` with no PAM (T-115): `--totp FILE`
//! holds a secret in base32, mode 0600, and a key that logs in must then
//! give the one-time code of RFC 6238 (HMAC-SHA-1, 30 s, six digits) by
//! keyboard-interactive. `--totp-new FILE` makes a secret.
//!
//! The state beside the secret, `FILE.used`, keeps the last step that let
//! a login in and each key's failures (`state.rs`). Each serve process of
//! `--stdio` is one connection, so the state is a file, read and written
//! under the lock of the secret's file: a code is taken once across them,
//! and a key's waits hold across them.

pub mod code;
pub mod state;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pod_core::files::{read_own, Others};
use pod_core::lock::{FileLock, Mode};
use zeroize::Zeroizing;

pub use state::Checked;

/// How long a check waits for another process's lock of the secret.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The bytes of a new secret: 160 bits, as RFC 4226 recommends.
pub const NEW_SECRET: usize = 20;

/// The prompt of keyboard-interactive.
pub const PROMPT: &str = "One-time code: ";

/// The secret of `--totp`, and where its state is.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    path: PathBuf,
    state: PathBuf,
}

impl std::fmt::Debug for Totp {
    // Never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp").field("path", &self.path).finish()
    }
}

/// The state file of the secret at `path`: `FILE.used`.
pub fn state_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".used");
    PathBuf::from(name)
}

impl Totp {
    /// The secret at `path`: a file of this user that others cannot read,
    /// as ssh reads a key, with one secret in base32. Its state is read and
    /// written once now, so a state that does not read, or a directory
    /// where none can be written, refuses the start and not a login. Err
    /// names the file and why, never the secret.
    pub fn open(path: &Path) -> Result<Totp, String> {
        let shown = path.display();
        let text = read_own(path, Others::NoAccess)?.ok_or_else(|| format!("{shown}: no such file"))?;
        let text = Zeroizing::new(text);
        let secret = code::decode_base32(&text).map_err(|why| format!("{shown}: the secret: {why}"))?;
        let totp = Totp { secret, path: path.to_path_buf(), state: state_path(path) };
        let _lock = totp.lock()?;
        let state = totp.read_state()?;
        totp.write_state(&state)?;
        Ok(totp)
    }

    /// Make a new secret at `path`, mode 0600, never over a file that is
    /// there. Its one line is the secret in base32, which an authenticator
    /// takes. Nothing is printed here, and the secret is not returned.
    pub fn create_new(path: &Path) -> Result<(), String> {
        let shown = path.display();
        let mut bytes = Zeroizing::new([0u8; NEW_SECRET]);
        aws_lc_rs::rand::fill(&mut bytes[..]).map_err(|_| "the system gave no random bytes".to_string())?;
        let text = code::encode_base32(&bytes[..]);
        let mut file = pod_core::files::create_new_private(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => format!("{shown} exists: serve never writes over a secret"),
            _ => format!("{shown}: {}", podssh_ws::text::file_said(path, &e)),
        })?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{shown}: {}", podssh_ws::text::said(&e)))
    }

    /// The secret's file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Judge `answer`, given by the key `key` at `now`, and keep the step
    /// or the failure in the state. Err: the state cannot be read or
    /// written, or the clock is before 1970; the login is then refused.
    pub fn check(&self, key: &str, answer: &[u8], now: SystemTime) -> Result<Checked, String> {
        let unix = now.duration_since(UNIX_EPOCH).map_err(|_| "the clock is before 1970".to_string())?.as_secs();
        let _lock = self.lock()?;
        let mut state = self.read_state()?;
        let checked = state::judge(&mut state, &self.secret, key, answer, unix);
        self.write_state(&state)?;
        Ok(checked)
    }

    /// The lock of the secret's file, which must be there: none is made.
    fn lock(&self) -> Result<FileLock, String> {
        let until = Instant::now() + LOCK_WAIT;
        loop {
            match FileLock::try_lock_existing(&self.path, Mode::Exclusive) {
                Ok(Some(lock)) => return Ok(lock),
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    return Err(format!(
                        "{}: another process held its lock for more than {} s",
                        self.path.display(),
                        LOCK_WAIT.as_secs()
                    ))
                }
                Err(e) => return Err(podssh_ws::text::said(&e)),
            }
        }
    }

    fn read_state(&self) -> Result<state::State, String> {
        let shown = self.state.display();
        match read_own(&self.state, Others::NoAccess)? {
            None => Ok(state::State::default()),
            Some(text) => state::parse(&text).map_err(|why| {
                format!(
                    "{shown}: {why}; remove it to start again (a code of the last minute may then be taken once \
                     more)"
                )
            }),
        }
    }

    fn write_state(&self, state: &state::State) -> Result<(), String> {
        let text = state::render(state);
        pod_core::files::replace(&self.state, text.as_bytes(), pod_core::files::Mode::Private)
            .map(|_| ())
            .map_err(|e| podssh_ws::text::said(&e))
    }
}

#[cfg(test)]
mod tests;
