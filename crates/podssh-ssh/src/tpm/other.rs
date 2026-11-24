//! The way to a TPM where podssh has none: Windows reaches its TPM through
//! TBS (`Tbsip_Submit_Command`), which podssh does not call (T-839). Each
//! use says so before anything is written.

use std::path::{Path, PathBuf};

use super::flow::Transport;

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
    Err("no TPM: podssh reaches a TPM through the device of a Unix kernel (/dev/tpmrm0), and this system has none"
        .into())
}

pub(super) fn open(place: &Place) -> Result<Box<dyn Transport>, String> {
    Err(format!("no TPM: {} cannot be opened on this system", place.describe()))
}
