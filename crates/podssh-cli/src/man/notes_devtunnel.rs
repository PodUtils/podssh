//! The notes of the Dev Tunnels road (T-755) for `podssh ssh`, `podssh
//! proxy` and `podssh doctor`, its variables, and its token file.

pub const SSH: &str = "devtunnel://[user@]TUNNEL[:PORT] reaches a port of the host of a Microsoft Dev Tunnels \
     tunnel, 22 by default, through the service's relay on port 443, in a build with the feature devtunnel \
     (70 in another build): TUNNEL is the tunnel's name, or ID.CLUSTER as the devtunnel tool shows it. podssh \
     asks the management API for the tunnel's relay and a connect token with your token, from the private file \
     of PODSSH_DEVTUNNEL_TOKEN_FILE (see FILES), never from argv; opens the relay's WebSocket through \
     HTTPS_PROXY when one is set, checked with podssh's trust; runs SSH to the tunnel's host inside it, whose key \
     must be one that the API names, with no user authentication; and opens a direct-tcpip channel to \
     127.0.0.1:PORT of that host, which carries the session. The host of the tunnel must have the port; \
     your own SSH server behind it checks you as on each road. The host key is recorded under \
     devtunnel://TUNNEL. A failure names its stage, management, websocket, ssh or channel: a token that the \
     API refuses and a host key that is not the tunnel's are 77, a tunnel that does not exist or has no host \
     connected and a refused port 69, a time limit or the API's 429 75, a token file or a setting that \
     cannot be used 78. A relay session that ends is opened again with a fresh connect token, a few times at \
     most, and never after a refused token. -p and Port give the port; --direct, -4, -6 and HostName cannot \
     go with it, and -J with it first makes the tunnel the first hop of a chain.";

pub const PROXY: &str = "podssh proxy devtunnel://TUNNEL:PORT carries the pipe to a port of a Dev Tunnels host, \
     in a build with the feature devtunnel, as podssh ssh does (see its notes): ssh -o \
     ProxyCommand='podssh proxy devtunnel://TUNNEL:%p' user@host.";

pub const DOCTOR: &str = "With --devtunnel TUNNEL[:PORT], in a build with the feature devtunnel, the section \
     devtunnel gives a line for that tunnel, after the roads over TCP that the run names: the road of a \
     devtunnel:// destination with the token of PODSSH_DEVTUNNEL_TOKEN_FILE, its time, and the host key of the \
     SSH server at the port, or why it has none. A failure names its stage: setup (the token file or a \
     setting), management, websocket, ssh, channel or reconnect. In another build the flag is refused (70).";

/// The variables of the road.
pub const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_DEVTUNNEL_TOKEN_FILE"],
        "The file of your token of Microsoft Dev Tunnels, for a devtunnel:// destination and podssh doctor \
      --devtunnel (see FILES). Unset or empty, the road is refused (78). A build with the feature devtunnel.",
    ),
    (
        &["PODSSH_DEVTUNNEL_API"],
        "Another base of the management API of Dev Tunnels, https://HOST[:PORT], in place of the service's \
      global one; http:// goes to this host alone, for a test. Another value is a configuration error (78). A \
      build with the feature devtunnel.",
    ),
];

/// The token file in FILES.
pub fn file() -> (Vec<String>, String) {
    (
        vec!["the file of PODSSH_DEVTUNNEL_TOKEN_FILE".to_string()],
        "Your token of Microsoft Dev Tunnels: one line, SCHEME TOKEN, as the management API takes it in \
         Authorization: github with a GitHub token (gh auth token prints one), aad with a token of Microsoft \
         Entra ID or a Microsoft account, or bearer. # starts a comment, and blank lines are skipped. podssh \
         reads it only as a regular file of yours that others cannot read (on Windows, as its access list \
         says); else, and for a line that cannot be used, the run is refused (78), in words that never hold \
         the token. The token goes to the management API alone, never to a line, the journal or --json. podssh \
         never writes it."
            .to_string(),
    )
}
