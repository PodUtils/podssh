//! The public node key of a state file (T-106): what a DERP server that
//! admits listed keys needs, `podssh relay serve --derp-keys FILE` among
//! them. The status line prints its first 8 hex digits alone, which name a
//! node to a person; an allowlist needs the whole key. The key is public:
//! it is the node's address on each DERP server and in each network map.
//! The private keys of the file never leave it here.

use std::path::Path;

use crate::node::NodeError;

/// The node key of the state file at `state_file`, as `nodekey:HEX`; a
/// missing file is made, with new keys, as `podssh ts --ts-state` makes
/// one, so that a key can be listed before the node first runs.
pub async fn node_key(state_file: &Path) -> Result<String, NodeError> {
    let config =
        tailscale::Config::default_with_key_file(state_file).await.map_err(|e| NodeError::Fork(e.to_string()))?;
    Ok(config.key_state.node_key.import().public.to_string())
}
