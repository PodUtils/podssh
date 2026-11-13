//! The device of WARP's road, in a build with the feature `warp`: pod-warp's
//! identity file in the cache, read, else registered once with the user's
//! acceptance of the Terms (with a team's token when one is given); its
//! tunnel, with the record read again from WARP's API when the front door
//! shows a new key, which the record then keeps (T-399); the door that
//! opened and the API's base that answered, kept in podssh's door file
//! (T-561, T-562); the run's settings of the endpoint and of the check
//! (T-560); HTTP/3 where UDP passes (T-582, `super::h3`); and the exit code
//! of each failure.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use podssh_warp::pod_core::{Class, Event, Events, Failure, Observer, Report, Stage};
use podssh_warp::pod_warp::store::{self, IdentityFile, Stored};
use podssh_warp::pod_warp::{self, Api};
use podssh_warp::{Road, Warp};
use podssh_ws::ProxyChoice;

use super::{
    accepted, probe_kept, Failed, ACCEPT_TERMS_ENV, API_ENV, DEVICE_FILE, DOOR_FILE, ENDPOINT_ENV, PROBE_ENV,
    TEAM_TOKEN_FILE_ENV,
};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_SOFTWARE, EX_TEMPFAIL, EX_UNAVAILABLE};

/// The code of a run that a failure of the road ends: 77 for the device
/// that the edge or the API refused, 78 for a setting or a record that
/// cannot be used, 75 for a limit of the API, 70 for what this build lacks,
/// 69 else: a proxy that refused the endpoint, and a front door that showed
/// another key than the record's after the record was read again (a proxy
/// that re-terminates TLS), too.
pub fn code(failure: &Failure) -> i32 {
    if pod_warp::tls::is_pin_mismatch(failure) || podssh_warp::at_proxy(failure) {
        return EX_UNAVAILABLE;
    }
    match pod_warp::api::api_status(failure) {
        Some(401 | 403) => return EX_NOPERM,
        Some(429) => return EX_TEMPFAIL,
        _ => {}
    }
    match failure.class {
        Class::Refused | Class::Revoked => EX_NOPERM,
        Class::Config | Class::Usage => EX_CONFIG,
        Class::Unsupported => EX_SOFTWARE,
        _ => EX_UNAVAILABLE,
    }
}

/// A device of the road: its identity file, and what the file holds.
#[derive(Clone)]
pub struct Device {
    pub path: PathBuf,
    stored: Stored,
}

impl Device {
    /// The endpoints that a run tries, in order: `PODSSH_WARP_ENDPOINT`
    /// alone when it is set, else the doors of the record.
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        match endpoint() {
            Ok(Some(at)) => vec![at],
            _ => self.stored.device.masque_endpoints(),
        }
    }
}

/// `PODSSH_WARP_PROBE`: whether the run checks that a packet crosses a new
/// tunnel.
fn probe() -> Result<bool, Failed> {
    probe_kept(std::env::var(PROBE_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))
}

/// `PODSSH_WARP_ENDPOINT`: another endpoint, as `ADDRESS:PORT`.
fn endpoint() -> Result<Option<SocketAddr>, Failed> {
    match std::env::var(ENDPOINT_ENV).ok().filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(text) => text
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| (format!("{ENDPOINT_ENV}={text}: an address and a port, as 162.159.198.2:443"), EX_CONFIG)),
    }
}

/// `PODSSH_WARP_API`: another base of WARP's API, `https://HOST[:PORT]`,
/// tried first (T-562).
fn api_route() -> Result<Option<String>, Failed> {
    match std::env::var(API_ENV).ok().filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(text) => match pod_warp::api::bases(Some(&text)) {
            Ok(bases) => Ok(bases.into_iter().next()),
            Err(why) => {
                Err((format!("{API_ENV}={text}: {}, as https://api.cloudflareclient.com", why.text()), EX_CONFIG))
            }
        },
    }
}

/// The team's token of `PODSSH_WARP_TEAM_TOKEN_FILE`, from a private file;
/// the token is never shown.
fn team_token() -> Result<Option<zeroize::Zeroizing<String>>, Failed> {
    let Some(path) = std::env::var_os(TEAM_TOKEN_FILE_ENV) else { return Ok(None) };
    let path = PathBuf::from(path);
    let text =
        podssh_relay::cache::read_private(&path).map_err(|why| (format!("{TEAM_TOKEN_FILE_ENV}: {why}"), EX_CONFIG))?;
    let token = zeroize::Zeroizing::new(text.trim().to_string());
    if token.is_empty() || token.contains(['\r', '\n']) {
        return Err((format!("{TEAM_TOKEN_FILE_ENV}: {} holds no token on one line", path.display()), EX_CONFIG));
    }
    Ok(Some(token))
}

/// The device's record where the cache holds one.
fn path_found() -> Option<PathBuf> {
    let found = podssh_relay::cache::read_dirs().into_iter().map(|dir| dir.join(DEVICE_FILE));
    found.into_iter().find(|path| std::fs::symlink_metadata(path).is_ok())
}

/// The place of a new record: the first directory of the cache that takes
/// a private file.
fn path_new() -> Result<PathBuf, Failed> {
    let mut refused = Vec::new();
    for dir in podssh_relay::cache::candidate_dirs() {
        match podssh_relay::cache::private_dir(&dir) {
            Ok(()) => return Ok(dir.join(DEVICE_FILE)),
            Err(e) => refused.push(format!("{}: {e}", dir.display())),
        }
    }
    let line = match refused.is_empty() {
        true => format!("{} is none, so podssh keeps no device of WARP's road", podssh_relay::cache::DIR_ENV),
        false => format!("no directory of the cache takes {DEVICE_FILE} ({})", refused.join("; ")),
    };
    Err((line, EX_CONFIG))
}

/// The device of the record in the cache; `None` with no record. It never
/// registers: `podssh doctor` reads it so (T-374). A setting that cannot be
/// used is said before the record is read.
pub fn kept() -> Result<Option<Device>, Failed> {
    endpoint()?;
    probe()?;
    api_route()?;
    super::h3::mode()?;
    super::h3::no_server()?;
    let Some(path) = path_found() else { return Ok(None) };
    let stored = store::load(&IdentityFile::new(&path)).map_err(|why| {
        let line = format!("the device's record {}: {}; remove it to register again", path.display(), why.chain());
        (line, EX_CONFIG)
    })?;
    Ok(Some(Device { path, stored }))
}

/// The device: [`kept`]; else a new one, registered when the user accepted
/// the Terms, whose record is kept. A record that cannot be read is a
/// configuration error that names the file, never one that registers again
/// on its own.
pub async fn device(say: &(dyn Fn(&str) + Sync), verbose: &(dyn Fn(&str) + Sync)) -> Result<Device, Failed> {
    if let Some(device) = kept()? {
        return Ok(device);
    }
    let yes = accepted(std::env::var(ACCEPT_TERMS_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))?;
    if !yes {
        let line = format!(
            "WARP's road needs a device, which podssh registers once with Cloudflare's API under Cloudflare's \
             Terms ({}); {ACCEPT_TERMS_ENV}=yes accepts them, and the device's record is kept in the cache",
            podssh_warp::terms_url()
        );
        return Err((line, EX_CONFIG));
    }
    let team = team_token()?;
    let path = path_new()?;
    say("registering a device with WARP's API, once: its record is kept in the cache");
    let first: Vec<String> = api_route()?.into_iter().collect();
    let api = podssh_warp::api(&ProxyChoice::FromEnvironment, &first, team.as_ref().map(|t| t.as_str()));
    let road = run_road(false)?;
    let settings = podssh_warp::settings(api.clone(), &road, Report::default());
    let file = IdentityFile::new(&path);
    let warp = pod_warp::Warp::register_or_load(settings, &file).await.map_err(|f| (f.chain(), code(&f)))?;
    if let Some(base) = api.answered() {
        verbose(&format!("WARP's API answered at {base}"));
    }
    verbose(&format!("the device's record is in {}", path.display()));
    keep_door(None, api.answered().as_deref());
    let stored = Stored { device: warp.device().clone(), identity: warp.identity().clone(), foreign: false };
    Ok(Device { path, stored })
}

/// The road of this run, over HTTP/3 or not.
fn run_road(h3: bool) -> Result<Road, Failed> {
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    Ok(Road { proxy: ProxyChoice::FromEnvironment, endpoint: endpoint()?, probe: probe()?, h3, limit })
}

/// The door that opened last and the API's base that answered last, from
/// podssh's door file; a door that is old or not of `device` is none.
fn door_state(device: &Device) -> (Option<SocketAddr>, Option<String>) {
    let Some(text) = podssh_relay::cache::load_file(DOOR_FILE) else { return (None, None) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let door = pod_warp::door::door_from(&text, now, &device.stored.device.masque_endpoints());
    let api =
        serde_json::from_str::<serde_json::Value>(&text).ok().and_then(|doc| doc["api"].as_str().map(String::from));
    (door, api)
}

/// Keep `door` and `api` in podssh's door file: the text of
/// `pod_warp::door::door_text`, with the API's base beside it.
fn keep_door(door: Option<SocketAddr>, api: Option<&str>) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut doc = match door {
        Some(door) => serde_json::from_str(&pod_warp::door::door_text(door, now)).unwrap_or_default(),
        None => serde_json::json!({ "schema": 1 }),
    };
    if let (Some(api), Some(map)) = (api, doc.as_object_mut()) {
        map.insert("api".into(), serde_json::Value::String(api.into()));
    }
    let _ = podssh_relay::cache::store_file(DOOR_FILE, doc.to_string().as_bytes());
}

/// The lines and the decisions of the crate in a run.
#[derive(Default)]
struct Seen {
    lines: Mutex<Vec<String>>,
    fresh: AtomicBool,
}

impl Events for Seen {
    fn event(&self, event: Event) {
        self.lines.lock().unwrap_or_else(PoisonError::into_inner).push(event.text);
    }
}

impl Observer for Seen {
    fn decision(&self, decision: &'static str, outcome: &str) {
        if decision == "warp.door" && outcome == "fresh-record" {
            self.fresh.store(true, Ordering::Relaxed);
        }
    }
}

impl Seen {
    /// Say each line that came, once.
    fn say(&self, verbose: &(dyn Fn(&str) + Sync)) {
        for line in std::mem::take(&mut *self.lines.lock().unwrap_or_else(PoisonError::into_inner)) {
            verbose(&line);
        }
    }
}

/// The tunnel of `device` on `road`: the door that opened last first; a
/// new key of the front door, which WARP's API gave, goes into the record
/// (T-399); the door that opened and the API's base go into the door file.
async fn open_on(
    device: &mut Device,
    api: &Api,
    road: &Road,
    door: Option<SocketAddr>,
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<Warp, Failure> {
    let seen = Arc::new(Seen::default());
    let report = Report { events: seen.clone(), observer: seen.clone() };
    let settings = podssh_warp::settings(api.clone(), road, report);
    let mut warp = pod_warp::Warp::from_stored(settings, device.stored.clone()).with_won_door(door);
    let opened = podssh_warp::open(&warp, road).await;
    seen.say(verbose);
    if seen.fresh.load(Ordering::Relaxed) && warp.refresh().await.is_ok() {
        match warp.save(&device.path) {
            Ok(()) => {
                device.stored.device = warp.device().clone();
                verbose("WARP's API gave its endpoint a new key, which the device's record keeps");
            }
            Err(why) => verbose(&format!(
                "the device's record was not written again ({}): the next run asks again",
                why.chain()
            )),
        }
    }
    if road.endpoint.is_none() {
        let won = opened.as_ref().ok().and_then(|w| w.endpoint);
        keep_door(won, api.answered().as_deref());
    }
    opened
}

/// The tunnel of `device` through the environment's proxy, at each of its
/// doors in turn (T-561), the door that opened last first.
pub async fn tunnel(device: &mut Device, verbose: &(dyn Fn(&str) + Sync)) -> Result<Warp, Failure> {
    let (door, kept_api) = door_state(device);
    let first: Vec<String> = api_route().ok().flatten().into_iter().chain(kept_api).collect();
    let api = podssh_warp::api(&ProxyChoice::FromEnvironment, &first, None);
    let (h2_road, h3_road) = match (run_road(false), run_road(true)) {
        (Ok(h2), Ok(h3)) => (h2, h3),
        (Err((line, _)), _) | (_, Err((line, _))) => {
            return Err(Failure::new(Stage::Warp, Class::Config, line));
        }
    };
    if !h2_road.probe {
        verbose(&format!("{PROBE_ENV}=no: WARP's tunnel is taken as it opens, with no packet through it proven"));
    }
    // HTTP/3 where UDP passes (T-582): first when the user asks, else after
    // HTTP/2 failed to reach the endpoint; a mode that cannot be read was
    // refused before the record was.
    let h3 = super::h3::mode().unwrap_or(super::h3::Mode::Auto);
    if h3 == super::h3::Mode::First {
        verbose("trying WARP's road over HTTP/3, where UDP passes");
        if let Ok(warp) = open_on(device, &api, &h3_road, door, verbose).await {
            return Ok(said(warp, verbose));
        }
    }
    let mut opened = open_on(device, &api, &h2_road, door, verbose).await;
    if h3 == super::h3::Mode::Auto {
        opened = match opened {
            Err(failure) if podssh_warp::worth_h3(&failure) => {
                verbose(&format!("WARP's road over HTTP/2: {}; HTTP/3 is tried", failure.chain()));
                match open_on(device, &api, &h3_road, door, verbose).await {
                    Ok(warp) => Ok(warp),
                    Err(over_h3) => Err(podssh_warp::both(failure, &over_h3)),
                }
            }
            other => other,
        };
    }
    opened.map(|warp| said(warp, verbose))
}

/// `warp`, said in `verbose`: its way, and the check of a packet through it.
fn said(warp: Warp, verbose: &(dyn Fn(&str) + Sync)) -> Warp {
    match (warp.h3, warp.endpoint) {
        (true, Some(at)) => verbose(&format!("WARP's tunnel opened over HTTP/3 at {at}")),
        _ => verbose(&format!("WARP's tunnel opened at {}", warp.via())),
    }
    if let Some(took) = warp.checked {
        verbose(&format!("a packet went inside WARP's tunnel and its answer came back in {} ms", took.as_millis()));
    }
    warp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each class of a failure has the code of podssh's road: the device's
    /// refusal 77, a setting 78, the API's limit 75, the rest 69.
    #[test]
    fn each_failure_has_its_code() {
        let of = |class| code(&Failure::new(Stage::Warp, class, "a line"));
        assert_eq!(of(Class::Refused), EX_NOPERM);
        assert_eq!(of(Class::Config), EX_CONFIG);
        assert_eq!(of(Class::Unsupported), EX_SOFTWARE);
        assert_eq!(of(Class::Unavailable), EX_UNAVAILABLE);
        assert_eq!(of(Class::Timeout), EX_UNAVAILABLE);
        let proxy = Failure::new(Stage::Proxy, Class::Refused, "the proxy refused CONNECT 162.159.198.2:443");
        assert_eq!(code(&Failure::caused(Stage::Warp, Class::Refused, "the front door", proxy)), EX_UNAVAILABLE);
    }
}
