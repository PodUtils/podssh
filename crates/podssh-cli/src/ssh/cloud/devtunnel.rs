//! `devtunnel://[user@]TUNNEL[:PORT]` (T-755): a port of the host of a
//! Microsoft Dev Tunnels tunnel, 22 by default, through the service's relay
//! on port 443, through `HTTPS_PROXY` when one is set, with no relay of
//! podssh's: the management API gives the tunnel's relay and a connect
//! token for the user's token, the relay carries SSH to the tunnel's host,
//! and a `direct-tcpip` channel of it reaches `127.0.0.1:PORT` there
//! (`podssh_relay::devtunnel`, over `pod-devtunnel`). TUNNEL is the
//! tunnel's name, or `ID.CLUSTER` as the vendor's tools show it.
//!
//! The user's token comes from the private file of
//! [`podssh_relay::devtunnel::TOKEN_FILE_ENV`], never from argv. The road is
//! in a build with the feature `devtunnel` only; without it, a
//! `devtunnel://` destination is refused before anything connects, with
//! exit 70.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::ssh::transport::{Duplex, NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "devtunnel://";

/// A port of a tunnel's host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `NAME` or `ID.CLUSTER`, lower case.
    pub tunnel: String,
    pub port: u16,
}

impl Target {
    /// The tunnel as messages and `known_hosts` show it.
    pub fn shown(&self) -> String {
        format!("{SCHEME}{}", self.tunnel)
    }
}

/// A part of a tunnel's name: lower-case letters, digits and `-`, as the
/// service names a tunnel, its id and its cluster.
fn label(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// `devtunnel://[user@]TUNNEL[:PORT]` as its user and target; `None` for
/// another destination.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Target)>, String> {
    let Some(rest) = text.strip_prefix(SCHEME) else { return Ok(None) };
    let (user, rest) = super::user_of(text, rest.trim_end_matches('/'))?;
    let (tunnel, port) = super::port_of(text, rest)?;
    let tunnel = tunnel.to_ascii_lowercase();
    let usable = match tunnel.split_once('.') {
        None => label(&tunnel),
        Some((id, cluster)) => label(id) && label(cluster),
    };
    if !usable {
        return Err(format!("{text:?}: give it as {SCHEME}[user@]TUNNEL[:PORT], TUNNEL a name or ID.CLUSTER"));
    }
    Ok(Some((user, Target { tunnel, port })))
}

/// Whether `destination` names a tunnel on this road.
pub fn is_devtunnel(destination: &str) -> bool {
    destination.starts_with(SCHEME)
}

/// Why this build has no Dev Tunnels road, for `what` that needs it.
pub fn not_built(what: &str) -> String {
    format!(
        "{what}: the Dev Tunnels road is not in this build; build podssh with --features devtunnel \
         (cargo build -p podssh-cli --features devtunnel)"
    )
}

/// A line of the road, and the code of a run that it ends.
pub type Failed = (String, i32);

/// Where a line of the road goes.
pub type Say = Arc<dyn Fn(&str) + Send + Sync>;

/// The exit code of a failure of the road, by its class, in podssh's table
/// (`exitmap`): a refusal is 77, a timeout 75, a setting 78, the rest of
/// what did not answer 69.
#[cfg(feature = "devtunnel")]
pub fn code_of(class: podssh_relay::devtunnel::Class) -> i32 {
    use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_TEMPFAIL, EX_UNAVAILABLE, EX_USAGE};
    use podssh_relay::devtunnel::Class;
    match class {
        Class::Usage => EX_USAGE,
        Class::Config => EX_CONFIG,
        Class::Refused | Class::Revoked | Class::Policy => EX_NOPERM,
        Class::TempFail | Class::Timeout => EX_TEMPFAIL,
        Class::Unavailable | Class::NotFound | Class::Protocol | Class::Unsupported => EX_UNAVAILABLE,
    }
}

/// The line of a failure of the road: the tunnel, the crate's words, and
/// the stage that broke, which `podssh doctor` names too.
#[cfg(feature = "devtunnel")]
pub fn failed(shown: &str, failure: &podssh_relay::devtunnel::Failure) -> Failed {
    let stage = podssh_relay::devtunnel::stage_of(failure);
    (format!("{shown}: {} (stage {stage})", failure.chain()), code_of(failure.class))
}

/// The stream to `target` through the tunnel's relay. `say` gets a
/// reconnect, `verbose` the rest; neither ever gets a token.
#[cfg(feature = "devtunnel")]
pub async fn open(target: &Target, trust: &Trust, say: Say, verbose: Say) -> Result<Box<dyn Duplex>, Failed> {
    use podssh_relay::devtunnel::{lines, Road};
    let shown = target.shown();
    let proxy = podssh_ws::ProxyChoice::FromEnvironment;
    let road = Road::from_env(&target.tunnel, trust.clone(), proxy).map_err(|f| failed(&shown, &f))?;
    verbose(&format!("connecting to {shown}, port {}, through the relay of Dev Tunnels", target.port));
    let stream = road.open(target.port, lines::report(say, verbose)).await.map_err(|f| failed(&shown, &f))?;
    Ok(Box::new(stream))
}

/// In a build without the feature: the refusal, which `podssh ssh` says
/// before anything is resolved; a road that reaches here says it again.
#[cfg(not(feature = "devtunnel"))]
pub async fn open(target: &Target, _trust: &Trust, _say: Say, _verbose: Say) -> Result<Box<dyn Duplex>, Failed> {
    Err((not_built(&target.shown()), crate::exit_codes::EXIT_NOT_IMPLEMENTED))
}

/// The stream to `target`, as `podssh ssh` reaches a first hop.
pub(super) async fn reach(target: &Target, trust: &Trust, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let (info, more) = (log.clone(), log.clone());
    let say: Say = Arc::new(move |line: &str| info.info(line));
    let verbose: Say = Arc::new(move |line: &str| more.verbose(line));
    match open(target, trust, say, verbose).await {
        Ok(stream) => Ok(Reached { stream, relay: None, direct_proxy: None, layer: None }),
        Err((line, code)) => Err(NotReached { lines: vec![line], code }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devtunnel_a_destination_is_read() {
        let (user, target) = destination("devtunnel://me@My-Box").unwrap().unwrap();
        assert_eq!((user.as_deref(), target.tunnel.as_str(), target.port), (Some("me"), "my-box", 22));
        assert_eq!(target.shown(), "devtunnel://my-box");
        let (_, target) = destination("devtunnel://bcd123.usw2:2222/").unwrap().unwrap();
        assert_eq!((target.tunnel.as_str(), target.port), ("bcd123.usw2", 2222));
        assert_eq!(destination("tor://github.com").unwrap(), None);
        for bad in [
            "devtunnel://",
            "devtunnel://@box",
            "devtunnel://box:0",
            "devtunnel://a.b.c",
            "devtunnel://-box",
            "devtunnel://b_x",
            "devtunnel://box/path",
        ] {
            assert!(destination(bad).is_err(), "{bad}");
        }
        assert!(is_devtunnel("devtunnel://box") && !is_devtunnel("warp://box"));
    }

    #[cfg(feature = "devtunnel")]
    #[test]
    fn devtunnel_each_class_has_a_code_of_podssh_s_table() {
        use podssh_relay::devtunnel::Class;
        assert_eq!(code_of(Class::Refused), 77);
        assert_eq!(code_of(Class::NotFound), 69);
        assert_eq!(code_of(Class::Timeout), 75);
        assert_eq!(code_of(Class::Config), 78);
        assert!(not_built("devtunnel://box").contains("--features devtunnel"));
    }
}
