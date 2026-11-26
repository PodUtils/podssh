//! `podssh serve NAME` (T-107, Approach item 5): a node of the pair NAME on
//! the relay's road whose sessions podssh's own SSH server answers in this
//! process, with no TARGET and no listener: each session is one end of a
//! pipe, and serve speaks SSH on the other end, with the keys, the host key
//! and the settings of the command line. An operator reaches it as any
//! node (`podssh ssh node://NAME`, `podssh cp`), so a host that has no
//! sshd and may not listen gives a shell and its files through the relay.
//! Also the runner of a node whose sessions are pipes in this process
//! ([`with_handler`]), which UDP's flows share. Where serve keeps shells
//! (T-159), its layer names `keep.v1`.

use std::sync::{Arc, OnceLock};

use podssh_relay::e2e::ends::Node;
use podssh_relay::reverse::{self, E2e, Exit, Handler, Layered, NodeConfig, Opening, SessionId};
use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::server::{Control, Keys, Settings};
use tokio::io::DuplexStream;

use crate::node_upgrade as upgrade;

/// Each direction of the pipe between a session and serve.
const PIPE: usize = 256 * 1024;

/// How the first line names what the node serves.
pub(crate) const SHOWN: &str = "podssh serve, in this process";

/// What serve answers each session with.
pub(crate) struct Served {
    pub key: PrivateKey,
    pub keys: Keys,
    pub settings: Arc<Settings>,
    pub control: Control,
    /// Where the keys come from, read again on SIGHUP (T-855).
    pub sources: crate::serve_keys::Sources,
}

static SERVED: OnceLock<Served> = OnceLock::new();

/// The server of this process's node; `false` when one was set already.
pub(crate) fn set(served: Served) -> bool {
    SERVED.set(served).is_ok()
}

/// Whether this process's node is `podssh serve NAME`.
pub(crate) fn serving() -> bool {
    SERVED.get().is_some()
}

/// Whether this process's node is `podssh serve NAME` and keeps shells
/// (T-159): its layer then names `keep.v1`, which `~d` and `--attach` need.
pub(crate) fn keeps() -> bool {
    SERVED.get().is_some_and(|s| !s.settings.keep_lease.is_zero())
}

/// SIGHUP reads serve's keys again while the guard lives (T-855); nothing
/// for a node of another kind. Called in the node's runtime.
pub(crate) fn hangups() -> crate::serve_keys::Hangups {
    match SERVED.get() {
        Some(s) => crate::serve_keys::Hangups::start(
            s.sources.clone(),
            s.keys.clone(),
            s.control.clone(),
            s.settings.revoke_ends_sessions,
        ),
        None => crate::serve_keys::Hangups::none(),
    }
}

/// What `podssh serve NAME` says of a door that is the pair's connect
/// token alone: serve has no TARGET, no `--allow` and no `--carrier`; its
/// own logins guard each session (T-869).
const SERVE_DOOR: &str = "whoever holds the pair's connect token reaches this node's door, and podssh serve in this \
                          process answers each session there: its authorized keys alone guard each login";

/// The line of a node whose door is the pair's connect token alone:
/// serve's own where this process's node is `podssh serve NAME`, else
/// `other`, the line of a node with a TARGET.
pub(crate) fn open_door(other: &'static str) -> &'static str {
    door_of(serving(), other)
}

fn door_of(serving: bool, other: &'static str) -> &'static str {
    if serving {
        SERVE_DOOR
    } else {
        other
    }
}

/// Each session: one end of a pipe, whose other end serve answers.
pub(crate) struct Sessions;

impl Handler for Sessions {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let Some(served) = SERVED.get() else {
            return Box::pin(async { Err("podssh serve: no server in this process".to_string()) });
        };
        let (near, far) = tokio::io::duplex(PIPE);
        let (key, keys) = (served.key.clone(), served.keys.clone());
        let (settings, control) = (served.settings.clone(), served.control.clone());
        tokio::spawn(async move {
            if let Err(why) = podssh_ssh::server::serve_under(far, key, keys, settings, control).await {
                podssh_ssh::err_line!("podssh serve: a session ended: {why}");
            }
        });
        Box::pin(async move { Ok(near) })
    }
}

/// Run the node with `inner` opening each session's target, as the TCP
/// target's arms of `node.rs` do: at `open` with no layer, or after the
/// layer's handshake, with the channel above the layer. Its targets are
/// pipes in this process, which an upgrade cannot move (T-668).
pub(crate) async fn with_handler<H>(config: &mut NodeConfig<'_>, inner: H, plain: bool, channel: Option<Node>) -> Exit
where
    H: Handler<Stream = DuplexStream>,
{
    let settings = if keeps() { crate::layered::ssh_settings() } else { crate::layered::settings() };
    let budget = reverse::layered::NODE_BUDGET;
    let (stop, deadline) = (upgrade::stop, settings.resume_deadline);
    match (plain, channel) {
        (true, None) => Box::pin(reverse::run(config, Arc::new(inner), stop())).await,
        (true, Some(node)) => Box::pin(reverse::run(config, Arc::new(E2e::new(inner, node)), stop())).await,
        (false, None) => {
            let handler = Arc::new(Layered::with_keeper(inner, settings, budget, upgrade::pipe_keeper(deadline)));
            Box::pin(reverse::run(config, handler, stop())).await
        }
        (false, Some(node)) => {
            let keeper = upgrade::channel_keeper(&node, deadline);
            let handler = Arc::new(Layered::with_keeper(E2e::new(inner, node), settings, budget, keeper));
            Box::pin(reverse::run(config, handler, stop())).await
        }
    }
}

/// `podssh serve NAME`'s pair, looked at before the host key is made
/// (T-1043): the node's refusal when no usable pair is stored under NAME and
/// no road that a node with no pair takes unasked would serve it (DERP's,
/// Q50, or a tunnel's, Q78). `None` when the node may go on; a check that
/// cannot be made is the node's own to say.
pub(crate) fn no_road(name: &str) -> Option<crate::relay_settings::Refusal> {
    let checked = crate::pairs::check_label(name).and_then(|()| crate::pairs::stored(name).map(|_| ()));
    let refusal = checked.err()?;
    let node = crate::node::NodeArgs { name: Some(name.to_string()), ..Default::default() };
    let derp = !matches!(crate::node_derp::unasked(&node), Ok(None));
    let tunnel = crate::node_sshj::last_of_all(&node).is_some();
    (!derp && !tunnel).then_some(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// serve NAME's line names what it serves, and no flag that it lacks;
    /// a node with a TARGET keeps its own line.
    #[test]
    fn the_door_line_of_serve_names_serve_and_no_target() {
        let other = "warning: ... reaches TARGET ...";
        let line = door_of(true, other);
        for absent in ["TARGET", "--allow", "--carrier"] {
            assert!(!line.contains(absent), "{absent}: {line}");
        }
        assert!(line.contains("podssh serve") && line.contains("authorized keys"), "{line}");
        assert_eq!(door_of(false, other), other);
    }
}
