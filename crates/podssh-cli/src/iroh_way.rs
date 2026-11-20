//! What podssh gives the iroh road of `pod-iroh` (PodUtils/podcrates): its
//! TLS context, its resolver, the proxy of the environment and its way out,
//! as on its other roads; and the values of the variables PODSSH_IROH_*,
//! which the crate does not read. Each caller of the road takes them here.

use iroh::RelayUrl;
use pod_core::entropy::Entropy;
use pod_iroh::keys::{Key, Place};
use pod_iroh::pkarr::{self, Choice, Server};
use pod_iroh::relays::{self, Source};
use pod_iroh::tuning::Tuning;
use pod_iroh::{Options, Udp};
use podssh_ws::ProxyChoice;

/// The variables of the road, by the names that the manual gives (T-165,
/// T-350, T-359, T-665). pod-iroh names the same in its words; a test
/// checks that the two agree.
const RELAY_ENV: &str = "PODSSH_IROH_RELAY";
const PKARR_ENV: &str = "PODSSH_IROH_PKARR";
const UDP_ENV: &str = "PODSSH_IROH_UDP";
const QUIC_ENV: &str = "PODSSH_IROH_QUIC";

/// What a user does when a relay refuses this build's iroh, in the notice
/// of the refusal (T-348).
pub const REMEDY: &str = "podssh update brings a newer podssh, or --iroh-relay URL names a relay that serves this one";

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The relays of `flag` (`--iroh-relay`), else of PODSSH_IROH_RELAY, else
/// the table, after the iroh relays of the net's own relay members (T-720).
pub fn relays(flag: Option<&str>) -> Result<(Vec<RelayUrl>, Source), String> {
    let (list, source) = relays::select(flag, var(RELAY_ENV))?;
    Ok(match source {
        Source::Table => (net_first(&crate::relay_deployments::net_iroh_relays(), list), source),
        _ => (list, source),
    })
}

/// The net's relays (`net`, each checked as a relay URL; one that is not is
/// passed over) before `table`, each once: the first that answers is the
/// home relay, so the net's peers meet on its own host, and n0's relays
/// stay behind it.
fn net_first(net: &[String], table: Vec<RelayUrl>) -> Vec<RelayUrl> {
    let mut list: Vec<RelayUrl> = net.iter().filter_map(|text| relays::parse_url(text).ok()).collect();
    for url in table {
        if !list.contains(&url) {
            list.push(url);
        }
    }
    list.dedup();
    list
}

/// The choice of PODSSH_IROH_PKARR.
pub fn pkarr_choice() -> Result<Choice, String> {
    pkarr::choice(var(PKARR_ENV).as_deref())
}

/// The server of pkarr for an end whose relays are `relays`: the one of
/// PODSSH_IROH_PKARR, else n0's for n0's relays (T-350).
pub fn pkarr_server(relays: &[RelayUrl]) -> Result<Option<Server>, String> {
    Ok(pkarr::server_for(&pkarr_choice()?, relays))
}

/// The probe of UDP of PODSSH_IROH_UDP (T-359).
pub fn udp() -> Udp {
    Udp::from_value(var(UDP_ENV).as_deref())
}

/// The arm of QUIC's settings of PODSSH_IROH_QUIC (T-665).
pub fn tuning() -> Result<Tuning, String> {
    Tuning::from_value(var(QUIC_ENV).as_deref())
}

/// The way out of each request of the road (`/ping`, pkarr, the question of
/// the version): the proxy of the environment, as on the other roads.
pub fn way() -> pod_ws::Way {
    podssh_ws::client::way(&ProxyChoice::FromEnvironment)
}

/// The options of an endpoint as podssh sets up its other roads: its TLS
/// context and its resolver, the proxy of the environment, and the
/// variables of UDP and of QUIC; a bad arm of QUIC is refused before
/// anything binds.
pub fn options() -> Result<Options, String> {
    let quic = tuning().map_err(|why| format!("the QUIC settings of the iroh road: {why}"))?;
    let mut options = Options::new(podssh_ws::tls::context().clone(), podssh_ws::resolve::resolver());
    options.proxy = podssh_ws::dial::settings(&ProxyChoice::FromEnvironment, false).proxy;
    options.udp = udp();
    options.quic = Some(quic);
    Ok(options)
}

/// The key kept at `place` in podssh's places, made when there is none.
pub fn load_key(place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    pod_iroh::keys::load(&podssh_relay::cache::pod_places(), place, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The net's relays come first, each once, a bad one passed over, and
    /// the table stays behind them; with no net, the table alone.
    #[test]
    fn the_net_s_relays_come_before_the_table() {
        let table = relays::defaults();
        assert_eq!(net_first(&[], table.clone()), table, "no net: the table");
        let net = ["https://relay.lab.example/".to_string(), "not a url".to_string(), table[0].to_string()];
        let list = net_first(&net, table.clone());
        assert_eq!(list[0].to_string(), "https://relay.lab.example/");
        assert_eq!(list[1], table[0], "a relay of the table that the net named is first once");
        assert_eq!(list.len(), table.len() + 1, "{list:?}");
    }

    /// The names that podssh reads are the names that pod-iroh says in its
    /// errors and lines.
    #[test]
    fn the_names_are_those_of_pod_iroh() {
        assert_eq!(RELAY_ENV, relays::ENV);
        assert_eq!(PKARR_ENV, pkarr::ENV);
        assert_eq!(UDP_ENV, pod_iroh::endpoint::UDP_ENV);
        assert_eq!(QUIC_ENV, pod_iroh::tuning::QUIC_ENV);
    }
}
