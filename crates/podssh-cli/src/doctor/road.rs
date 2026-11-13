//! The road that carried doctor's forward session (T-319, its Approach
//! item 5): a WebSocket, as each session first tries, or, once each relay
//! host failed and the way to one refused the upgrade, the HTTP road at that
//! host in its split or serial form, as `podssh ssh` and `podssh proxy`
//! take it. The forward line names the road, and `--json` gives it as the
//! line's `samples`, so that a user learns which road this place leaves.

use std::sync::Arc;

use podssh_relay::http_road::client::{End, Ended, Target};
use podssh_relay::http_road::Form;
use podssh_relay::open::Failure;
use podssh_relay::relay::RelayList;
use podssh_ssh::relay_stream::RelayStatus;
use podssh_ws::Trust;
use serde_json::{json, Value};
use tokio::io::DuplexStream;

use crate::http_road::Asked;

/// What tells how a session ended, by its road.
pub(super) enum Carrier {
    WebSocket(RelayStatus),
    Http { ended: Arc<Ended>, form: Form },
}

/// A forward session that opened: its stream, and its road.
pub(super) struct Carried {
    pub(super) stream: DuplexStream,
    pub(super) road: Road,
}

/// The road of a session, and the words of where it went, which name it.
pub(super) struct Road {
    pub(super) carrier: Carrier,
    pub(super) via: String,
}

impl Carried {
    /// A session of the WebSocket road through `host`; `road` the words of
    /// how it was carried (`, over HTTP/2 ...`, ` in cleartext`), or none.
    pub(super) fn websocket(stream: DuplexStream, status: RelayStatus, host: &str, road: &str) -> Carried {
        Carried { stream, road: Road { carrier: Carrier::WebSocket(status), via: websocket_via(host, road) } }
    }
}

impl Road {
    /// Why the session failed once it opened, with what its road said of
    /// its end: after an upgrade that passed, or after the HTTP road's open.
    pub(super) fn after_open(&self, why: &str) -> String {
        match &self.carrier {
            Carrier::WebSocket(status) => super::relay_checks::after_upgrade(why, status.get(), status.age()),
            Carrier::Http { ended, .. } => http_after(why, ended.get()),
        }
    }

    /// What the road said of the session's end, when it said something.
    pub(super) fn explain(&self) -> Option<String> {
        match &self.carrier {
            Carrier::WebSocket(status) => status.get().and_then(|end| end.explain()),
            Carrier::Http { ended, .. } => {
                let lines = crate::http_road::ssh_lines(ended.get(), &github());
                (!lines.is_empty()).then(|| lines.join("; "))
            }
        }
    }

    /// The road, for `--json`.
    pub(super) fn samples(&self) -> Value {
        match &self.carrier {
            Carrier::WebSocket(_) => json!({ "road": "websocket" }),
            Carrier::Http { form, .. } => json!({ "road": "http", "form": form.name() }),
        }
    }
}

fn github() -> String {
    podssh_ws::dial::authority(super::relay_checks::forward_host(), 22)
}

/// `HOST, over a WebSocket`, or the words that its road said instead.
pub(super) fn websocket_via(host: &str, road: &str) -> String {
    if road.is_empty() {
        format!("{host}, over a WebSocket")
    } else {
        format!("{host}{road}")
    }
}

/// `HOST, over its HTTP road in the FORM form`, and why.
pub(super) fn http_via(host: &str, form: Form) -> String {
    format!("{host}, over its HTTP road in the {} form, as the way refused the WebSocket upgrade", form.name())
}

/// Why the HTTP road's session failed, with the road's end.
fn http_after(why: &str, end: Option<End>) -> String {
    let opened = "the HTTP road opened";
    match end {
        Some(End::Closed { code, reason }) => format!("{opened}, then {why} (the role closed it: {code} {reason})"),
        Some(End::Failed(road)) => format!("{opened}, then {why} ({road})"),
        None => format!("{opened}, then {why}"),
    }
}

/// After each relay host failed: the HTTP road to GitHub's SSH port at the
/// first host whose upgrade the way refused, as `ssh` takes it; `None` when
/// no way refused one, or `PODSSH_HTTP_ROAD=no`.
pub(super) async fn after_relays(
    failure: &Failure,
    relays: &RelayList,
    trust: &Trust,
) -> Option<Result<Carried, String>> {
    let form = match crate::http_road::asked(std::env::var(crate::http_road::ENV).ok().as_deref()) {
        Ok(Asked::No) => return None,
        Ok(Asked::Auto) => None,
        Ok(Asked::Only(form)) => Some(form),
        Err(why) => return Some(Err(why)),
    };
    let relay = crate::http_road::refused_at(failure, relays)?;
    let target = Target { host: super::relay_checks::forward_host(), port: 22, family: None };
    Some(match crate::http_road::open(&relay, trust, target, form).await {
        Ok(opened) => {
            let via = http_via(&relay.host, opened.form);
            let carrier = Carrier::Http { ended: opened.ended, form: opened.form };
            Ok(Carried { stream: opened.stream, road: Road { carrier, via } })
        }
        Err(why) => Err(format!("the HTTP road at {}: {why}", relay.host)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line names the road: a WebSocket, the words of HTTP/2's or the
    /// cleartext road where they say more, or the HTTP road and its form.
    #[test]
    fn the_forward_line_names_the_road_that_answered() {
        assert_eq!(websocket_via("relay-a.test", ""), "relay-a.test, over a WebSocket");
        assert_eq!(websocket_via("relay-a.test", " in cleartext"), "relay-a.test in cleartext");
        let h2 = ", over HTTP/2 (RFC 8441), on a connection that it opened";
        assert_eq!(websocket_via("r", h2), format!("r{h2}"));
        let split = http_via("relay-a.test", Form::Split);
        assert!(split.starts_with("relay-a.test, over its HTTP road in the split form, as the way refused"), "{split}");
        assert!(http_via("r", Form::Serial).contains("in the serial form"));
    }

    /// `--json` gives the road, and the HTTP road's form.
    #[test]
    fn the_samples_give_the_road_and_its_form() {
        let (ours, _theirs) = tokio::io::duplex(8);
        let ws = Carried::websocket(ours, RelayStatus::default(), "r", "");
        assert_eq!(ws.road.samples(), json!({ "road": "websocket" }));
        assert_eq!(ws.road.explain(), None);
        let ended = Arc::new(Ended::default());
        let http = Road { carrier: Carrier::Http { ended: ended.clone(), form: Form::Serial }, via: "r".into() };
        assert_eq!(http.samples(), json!({ "road": "http", "form": "serial" }));
        assert_eq!(http.explain(), None, "no end yet");
        ended.set_once(End::Closed { code: 1009, reason: "session byte cap".into() });
        assert!(http.explain().unwrap().contains(": 1009 session byte cap"), "{:?}", http.explain());
        let after = http.after_open("no banner");
        assert_eq!(after, "the HTTP road opened, then no banner (the role closed it: 1009 session byte cap)");
    }

    /// The HTTP road's failure after its open is no upgrade's.
    #[test]
    fn a_failure_on_the_http_road_names_that_road() {
        assert_eq!(http_after("no banner", None), "the HTTP road opened, then no banner");
        let failed = http_after("no banner", Some(End::Failed("no answer within 60 s".into())));
        assert_eq!(failed, "the HTTP road opened, then no banner (no answer within 60 s)");
        assert!(!failed.contains("upgrade"));
    }
}
