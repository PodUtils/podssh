//! The gate of each request of a connection (T-107, T-114, T-117, T-842):
//! the rules in force for each request, apart from the handler so that each
//! file stays short. The rules under which a key logs in are
//! `handler/auth.rs` (T-116), which says each refusal in the audit log.

use std::sync::Arc;

use super::super::stop::{Stage, STOPPING};
use super::super::{share_view, Rules};
use super::Served;

impl Served {
    /// Whether the server serves and this connection was not ended.
    pub(super) fn serving(&self) -> bool {
        self.control.stage() == Stage::Serving && self.conn.ended().is_none()
    }

    /// The rules in force, or the words of a refusal: before a login, or
    /// once the server stops (T-117), which takes no new request.
    pub(super) fn rules(&self) -> Result<Arc<Rules>, String> {
        if self.control.stage() != Stage::Serving {
            return Err(STOPPING.to_string());
        }
        // A key that a reload took out runs nothing more (T-842).
        if let Some(told) = self.conn.ended() {
            return Err(told);
        }
        if self.viewer.is_some() {
            return Err(share_view::RUNS_NOTHING.to_string());
        }
        self.rules.clone().ok_or_else(|| "no key logged in".to_string())
    }
}
