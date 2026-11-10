//! The last fallbacks of the race of `podssh ssh node://NAME` (Q78), apart
//! from `roads.rs` for the length of that file: a node's Pinggy tunnel
//! (T-548), its alias at Serveo (T-549), its name at ssh-j.com (T-570),
//! then its tunnel of HTTP made by `ssh -R` (T-565), the last of all; each
//! starts as its own `push` says.

use podssh_relay::session::race::Start;

use super::{Going, Kind, Roads};

impl<'a> Roads<'a> {
    /// The attempts of the last fallbacks, in their order, after the others.
    pub(super) fn push_last<'s>(&'s self, list: &mut Vec<(Start, Going<'s>)>, kinds: &mut Vec<Kind>) {
        if let Some(pinggy) = &self.pinggy {
            pinggy.push(list, kinds, self.record.as_ref());
        }
        if let Some(serveo) = &self.serveo {
            serveo.push(list, kinds);
        }
        if let Some(sshj) = &self.sshj {
            sshj.push(list, kinds);
        }
        if let Some(tunnel) = &self.tunnel {
            tunnel.push(list, kinds, self.record.as_ref());
        }
    }
}
