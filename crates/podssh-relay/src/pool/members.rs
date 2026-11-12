//! The relay members of a net (T-617), asked for their lists of hosts:
//! `pod-relay` of PodUtils/podcrates (T-684). The members of the process are
//! in the settings of podssh's context.

use podssh_ws::Trust;

pub use pod_relay::pool::members::*;

use crate::relay::RelayList;

/// The relay members of the net that this host holds, for this process: the
/// first [`MOST`] of them, so that a net of many asks no more.
pub fn set_by_net(mut members: Vec<Member>) {
    members.truncate(MOST);
    crate::context::give_members(members);
}

/// The members that [`set_by_net`] gave.
pub fn of_process() -> Vec<Member> {
    crate::context::members()
}

/// The last ask of `member` that the cache keeps.
pub fn last_ask(member: &Member) -> Option<Ask> {
    pod_relay::pool::members::last_ask(&crate::context::cache(), member)
}

/// Ask each member of the process that is due for its list, and keep each
/// list that holds: how many were newly kept.
pub async fn ask_due(trust: &Trust) -> usize {
    pod_relay::pool::members::ask_due(&crate::context::process(), trust).await
}

/// `list` with the hosts of the lists that this run's asks kept.
pub async fn refreshed(list: &RelayList, trust: &Trust) -> RelayList {
    pod_relay::pool::members::refreshed(&crate::context::process(), list, trust).await
}
