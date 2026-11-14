//! The GSRN road (T-707): two podssh ends that share a secret meet at the
//! relay of gsocket, at the address that the secret gives, and speak TLS
//! with SRP there, so the relay carries bytes that it cannot read. The
//! protocol is `pod-gsr`'s and the relay's facts are the data file
//! `hackerschoice-gsr` of `pod-services`; this crate gives them podssh's way
//! out (`podssh_ws::dial`, through `HTTPS_PROXY` when one is set) and the
//! words of podssh's lines. It reads no variable and prints nothing; the
//! secret comes from the caller, which read it from a private file.

use std::sync::Arc;
use std::time::Duration;

use pod_core::entropy::{Entropy, OsEntropy};
use pod_core::{Class, Stage};
use podssh_ws::ProxyChoice;
use tokio::time::Instant;
use zeroize::Zeroizing;

pub use pod_core::{Dial, Failure};
pub use pod_gsr::{End, Role, Settings, Stream};

/// The bound of the TLS handshake once the relay paired the two ends:
/// `pod_gsr::open` leaves it to its caller.
pub const TLS_LIMIT: Duration = Duration::from_secs(30);

/// The settings of the relay, from `pod-services`' data file.
pub fn settings() -> Result<Settings, String> {
    Settings::of_data().map_err(|failure| failure.chain())
}

/// The party that runs the relay, as the data file names it, for the line
/// of a third party.
pub fn party() -> String {
    pod_services::get(pod_gsr::SERVICE).map_or_else(|| "an unnamed party".to_string(), |s| s.party().to_string())
}

/// The relay's host and port for `secret`, as a line names it: the shard
/// that the secret gives. It holds nothing of the secret but its shard.
pub fn host_of(settings: &Settings, secret: &str) -> String {
    let identity = pod_gsr::Identity::new(secret, settings);
    format!("{}:{}", identity.host(settings), settings.port)
}

/// Whether `secret` is one that the relay takes: not empty, and not longer
/// than the service's limit. The words never hold the secret.
pub fn check_secret(settings: &Settings, secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("the secret is empty".into());
    }
    if secret.len() > settings.secret_max {
        return Err(format!(
            "the secret is {} bytes, and the relay takes at most {}",
            secret.len(),
            settings.secret_max
        ));
    }
    Ok(())
}

/// OpenSSL's version, once the SRP context of each side was built with no
/// connection: a self-test of this binary's TLS with SRP.
pub fn check_tls(settings: &Settings) -> Result<&'static str, String> {
    pod_gsr::check_tls(settings).map_err(|failure| failure.chain())
}

/// podssh's way out for `proxy`, as `pod_core::Dial`.
pub fn dialer(proxy: &ProxyChoice) -> Arc<dyn Dial> {
    Arc::new(podssh_ws::dial::dialer(proxy, false))
}

/// A tunnel through the relay as `role`, with `secret`: the dial and the wait
/// for the peer end at `wait`, the TLS handshake [`TLS_LIMIT`] after.
pub async fn open(
    dial: &dyn Dial,
    settings: &Settings,
    role: Role,
    secret: &str,
    wait: Duration,
) -> Result<Stream, Failure> {
    let deadline = Instant::now() + wait;
    let mut entropy = OsEntropy;
    let opening = pod_gsr::open(dial, settings, role, secret, &mut entropy, deadline);
    match tokio::time::timeout(wait + TLS_LIMIT, opening).await {
        Ok(opened) => opened,
        Err(_) => Err(Failure::new(Stage::Tls, Class::Timeout, "no TLS with the peer within the time limit")),
    }
}

/// Whether `failure` is the end of a wait with no peer, which a listener
/// meets again at once: the relay's idle limit, or this side's deadline.
pub fn no_peer_yet(failure: &Failure) -> bool {
    failure.class == Class::Timeout && failure.stage == Stage::Relay
}

/// A secret that nobody holds, of 24 hex digits, whose address is on the
/// shard of `like` when one is given: a probe of the relay that reaches the
/// shard of the user's own secret, and pairs with nobody.
pub fn throwaway(settings: &Settings, like: Option<&str>) -> Result<Zeroizing<String>, String> {
    let wanted = like.map(|secret| pod_gsr::Identity::new(secret, settings).shard(settings));
    // 26 shards: each try lands on the wanted one with odds of 1 in 26, so
    // 4096 tries miss it with odds far below one in a billion.
    for _ in 0..4096 {
        let mut bytes = [0u8; 12];
        OsEntropy.fill(&mut bytes).map_err(|_| "no random bytes on this host".to_string())?;
        let text = Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let shard = pod_gsr::Identity::new(&text, settings).shard(settings);
        if wanted.is_none_or(|wanted| wanted == shard) {
            return Ok(text);
        }
    }
    Err("no secret on the shard of yours after 4096 tries".into())
}

/// One round trip of the control protocol with the relay: a `CONNECT` with
/// a secret that nobody holds ([`throwaway`]) on the shard of `like`, which
/// the relay answers with its status "no peer is listening". The time of
/// the answer; an answer of another kind, or none, is the failure.
pub async fn round_trip(
    dial: &dyn Dial,
    settings: &Settings,
    like: Option<&str>,
    limit: Duration,
) -> Result<Duration, String> {
    let secret = throwaway(settings, like)?;
    let started = std::time::Instant::now();
    match open(dial, settings, Role::Connect, &secret, limit).await {
        // Status 2 alone: a relay that closed the connection is Unavailable
        // too, with no answer.
        Err(failure) if failure.class == Class::Unavailable && failure.text().contains("(code 2)") => {
            Ok(started.elapsed())
        }
        Err(failure) => Err(failure.chain()),
        // Nobody holds the secret: a peer here would be a defect of the relay.
        Ok(_) => Err("a peer answered a secret that nobody holds".into()),
    }
}

/// Whether a registration with no traffic but the relay's pings lives
/// `hold`: a `LISTEN` with a secret that nobody holds, until this side's
/// deadline. A proxy that cuts an idle tunnel ends it first.
pub async fn idle_holds(dial: &dyn Dial, settings: &Settings, hold: Duration) -> Result<(), String> {
    let secret = throwaway(settings, None)?;
    match open(dial, settings, Role::Listen, &secret, hold).await {
        Err(failure) if no_peer_yet(&failure) => Ok(()),
        Err(failure) => Err(failure.chain()),
        Ok(_) => Err("a peer answered a secret that nobody holds".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_of_a_secret_is_its_shard_of_the_data_file_s_domain() {
        let settings = settings().expect("the data file");
        // The vector of pod-gsr and gsocket: testsecret123 is on shard l.
        let host = host_of(&settings, "testsecret123");
        assert!(host.starts_with("l."), "{host}");
        assert!(host.ends_with(&format!(".{}:{}", settings.domain, settings.port)), "{host}");
    }

    #[test]
    fn a_secret_too_long_or_empty_is_refused_in_words_that_do_not_hold_it() {
        let settings = settings().expect("the data file");
        let long = "s".repeat(settings.secret_max + 1);
        let why = check_secret(&settings, &long).expect_err("too long");
        assert!(!why.contains(&long), "{why}");
        assert!(check_secret(&settings, "").is_err());
        assert!(check_secret(&settings, "a-good-secret").is_ok());
    }

    #[test]
    fn a_throwaway_secret_is_on_the_shard_of_the_one_that_it_is_like() {
        let settings = settings().expect("the data file");
        let wanted = pod_gsr::Identity::new("testsecret123", &settings).shard(&settings);
        for _ in 0..8 {
            let secret = throwaway(&settings, Some("testsecret123")).expect("a secret");
            assert_ne!(secret.as_str(), "testsecret123");
            assert_eq!(pod_gsr::Identity::new(&secret, &settings).shard(&settings), wanted);
            check_secret(&settings, &secret).expect("a secret that the relay takes");
        }
    }

    #[test]
    fn the_tls_of_this_binary_has_srp() {
        let settings = settings().expect("the data file");
        let version = check_tls(&settings).expect("both contexts");
        assert!(version.starts_with("OpenSSL 3."), "{version}");
    }
}
