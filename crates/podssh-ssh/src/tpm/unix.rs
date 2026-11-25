//! The way to a TPM on Unix: the kernel's device with its resource manager,
//! `/dev/tpmrm0` (Linux 4.12 and later, FreeBSD), which keeps each
//! connection's handles apart and flushes them when it closes; or a socket
//! that the user names, as a software TPM (`swtpm socket --server
//! type=unixio`) gives one, speaking the same bytes. Nothing is assumed: a
//! container or a sandbox shows no such device, and the probe says so.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use pod_tpm::transport::{Device, Limits, Socket};
use pod_tpm::Transport;

use super::COMMAND_LIMIT;

/// Where the TPM is, and what kind of file it is.
#[derive(Debug, Clone)]
pub(super) struct Place {
    pub path: PathBuf,
    socket: bool,
}

impl Place {
    pub fn describe(&self) -> String {
        let kind = if self.socket { "the socket" } else { "the device" };
        format!("{kind} {}", self.path.display())
    }
}

/// The TPM of `named`, else `/dev/tpmrm0`.
pub(super) fn find(named: Option<&Path>) -> Result<Place, String> {
    find_in(Path::new("/dev"), named)
}

/// [`find`] in another directory of devices, for the tests.
pub(super) fn find_in(dev: &Path, named: Option<&Path>) -> Result<Place, String> {
    let path = match named {
        Some(path) => path.to_path_buf(),
        None => dev.join("tpmrm0"),
    };
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && named.is_none() => {
            let bare = dev.join("tpm0");
            return Err(if bare.exists() {
                format!(
                    "no TPM: this host shows {} but no {}, the kernel's resource manager; \
                     PODSSH_TPM_DEVICE={} uses it with no manager, while no other program does",
                    bare.display(),
                    path.display(),
                    bare.display()
                )
            } else {
                format!("no TPM: this host shows no {} (a container or a sandbox shows none)", path.display())
            });
        }
        Err(e) => return Err(format!("no TPM: {} cannot be read: {e}", path.display())),
    };
    let kind = meta.file_type();
    if kind.is_char_device() {
        return Ok(Place { path, socket: false });
    }
    if kind.is_socket() {
        return Ok(Place { path, socket: true });
    }
    Err(format!("no TPM: {} is neither a device nor a socket", path.display()))
}

/// A connection to the TPM of `place`: `pod-tpm`'s transport of a device
/// or of the socket of swtpm, each command bounded in time
/// ([`COMMAND_LIMIT`], as a TPM of hardware can take seconds for a primary
/// key) and in size.
pub(super) fn open(place: &Place) -> Result<Box<dyn Transport>, String> {
    let limits = Limits { command: COMMAND_LIMIT };
    if place.socket {
        let socket = Socket::connect_unix(&place.path, limits).map_err(|e| format!("no TPM: {e}"))?;
        return Ok(Box::new(socket));
    }
    let device = Device::open(&place.path, limits).map_err(|e| match e.class {
        pod_core::Class::Permission => {
            format!("no TPM: this user may not open {} ({e}); on most systems the group tss may", place.path.display())
        }
        _ => format!("no TPM: {} cannot be opened: {e}", place.path.display()),
    })?;
    Ok(Box::new(device))
}
