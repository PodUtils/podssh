//! `podssh serve NAME` (T-107, Approach item 5): a node of the pair NAME on
//! the relay's road whose sessions podssh's own SSH server answers in this
//! process, with no TARGET and no listener: each session is one end of a
//! pipe, and serve speaks SSH on the other end, with the keys, the host key
//! and the settings of the command line. An operator reaches it as any
//! node (`podssh ssh node://NAME`, `podssh cp`), so a host that has no
//! sshd and may not listen gives a shell and its files through the relay.
//! Also the runner of a node whose sessions are pipes in this process
//! ([`with_handler`]), which UDP's flows share.

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
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
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
