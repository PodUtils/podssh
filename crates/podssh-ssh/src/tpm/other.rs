//! The way to a TPM where podssh has none: a system that is neither Unix
//! (the kernel's device) nor Windows (the TPM Base Services). Each use says
//! so before anything is written.

use std::path::{Path, PathBuf};

use pod_tpm::Transport;

// Never made here: `find` refuses first.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct Place {
    pub path: PathBuf,
}

impl Place {
    pub fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

pub(super) fn find(_named: Option<&Path>) -> Result<Place, String> {
    Err("no TPM: podssh reaches a TPM through a Unix kernel's device (/dev/tpmrm0) or Windows' TPM Base Services, \
         and this system has neither"
        .into())
}

pub(super) fn open(place: &Place) -> Result<Box<dyn Transport>, String> {
    Err(format!("no TPM: {} cannot be opened on this system", place.describe()))
}
