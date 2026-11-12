//! The tunnel of `--devtunnel TUNNEL[:PORT]` (T-755): the road of a
//! `devtunnel://` destination, step by step (the management API with the
//! token of `PODSSH_DEVTUNNEL_TOKEN_FILE`, the relay's WebSocket, its SSH
//! to the tunnel's host, a channel to the port), then the host key of the
//! SSH server at that port. A failure names its stage, so that the user
//! knows whether the token, the proxy, the relay or the port stopped it. The
//! line holds no token: the crate's words hold none.

use podssh_ws::Trust;

use super::Report;
use crate::relay_settings::Refusal;
use crate::ssh::cloud::devtunnel::{self, Target};

/// The tunnel of the flag: `TUNNEL[:PORT]`, or a `devtunnel://` destination
/// as `podssh ssh` takes it. In a build without the feature, exit 70.
pub(super) fn asked(flag: Option<&str>) -> Result<Option<Target>, Refusal> {
    let Some(text) = flag else { return Ok(None) };
    if !cfg!(feature = "devtunnel") {
        let message = devtunnel::not_built("--devtunnel");
        return Err(Refusal { message, code: crate::exit_codes::EXIT_NOT_IMPLEMENTED });
    }
    let full = match devtunnel::is_devtunnel(text) {
        true => text.to_string(),
        false => format!("{}{text}", devtunnel::SCHEME),
    };
    match devtunnel::destination(&full) {
        Ok(Some((None, target))) => Ok(Some(target)),
        Ok(Some((Some(_), _))) => Err(Refusal::usage(format!("--devtunnel {text}: give no user, as no login is made"))),
        Ok(None) => Err(Refusal::usage(format!("--devtunnel {text}: give TUNNEL[:PORT]"))),
        Err(why) => Err(Refusal::usage(format!("--devtunnel {why}"))),
    }
}

/// The line of the tunnel.
#[cfg(feature = "devtunnel")]
pub(super) async fn check(report: &mut Report<'_>, target: &Target, trust: &Trust) {
    use podssh_relay::devtunnel::{lines, stage_of, Road};
    let shown = format!("{}:{}", target.shown(), target.port);
    let proxy = podssh_ws::ProxyChoice::FromEnvironment;
    let road = match Road::from_env(&target.tunnel, trust.clone(), proxy) {
        Ok(road) => road,
        Err(failure) => return report.fail("devtunnel", format!("{shown}: stage setup: {}", failure.chain())),
    };
    let started = std::time::Instant::now();
    let stream = match road.open(target.port, lines::quiet()).await {
        Ok(stream) => stream,
        Err(failure) => {
            let stage = stage_of(&failure);
            return report.fail("devtunnel", format!("{shown}: stage {stage}: {}", failure.chain()));
        }
    };
    let ms = started.elapsed().as_millis();
    let reached = format!("{shown}: the management API, the relay, its SSH and the channel in {ms} ms");
    match podssh_ssh::probe::host_key(stream, super::relay_checks::TIMEOUT).await {
        Ok(key) => {
            let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
            let kind = podssh_ssh::known_hosts::key_type(&key);
            report.ok("devtunnel", format!("{reached}; the port's SSH server has the {kind} host key {fingerprint}"));
        }
        // The port may serve another protocol than SSH: the road works.
        Err(why) => report.ok("devtunnel", format!("{reached}; no SSH host key at the port: {why}")),
    }
}

/// In a build without the feature, [`asked`] refused the flag already.
#[cfg(not(feature = "devtunnel"))]
pub(super) async fn check(report: &mut Report<'_>, target: &Target, _trust: &Trust) {
    report.fail("devtunnel", devtunnel::not_built(&target.shown()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devtunnel_the_flag_is_a_tunnel_and_a_port() {
        assert_eq!(asked(None).unwrap(), None);
        let asked = asked(Some("My-Box:2222"));
        if !cfg!(feature = "devtunnel") {
            assert_eq!(asked.unwrap_err().code, crate::exit_codes::EXIT_NOT_IMPLEMENTED);
            return;
        }
        let target = asked.unwrap().unwrap();
        assert_eq!((target.tunnel.as_str(), target.port), ("my-box", 2222));
        assert_eq!(super::asked(Some("devtunnel://box")).unwrap().unwrap().port, 22);
        for bad in ["me@box", "a.b.c", "box:0"] {
            assert_eq!(super::asked(Some(bad)).unwrap_err().code, crate::exit_codes::EXIT_USAGE, "{bad}");
        }
    }
}
