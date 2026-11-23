//! The delegated credential of a cover relay (#225, T-766): a token at
//! `POST /v1/delegate`, then the credential checked against the operator key
//! that the authenticated connection delivered, its issuer and name, its
//! window and the TLS exporter of that connection. The verifier is then run
//! against another name, a lapsed window and another exporter, and each must
//! be refused by the name that pod-cover gives it. A cover moves `/health`
//! and the documents off the public listener, so these lines stand in for the
//! relay check there.

use std::time::{SystemTime, UNIX_EPOCH};

use pod_cover::CredentialError;
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::token::{self, MintContext};
use podssh_ws::Trust;

use super::relay_checks::TIMEOUT;
use super::Report;

/// The check of the credential of `name` at the relay list's first host,
/// whose certificate must name it, and of the refusals beside it.
pub(super) async fn check(report: &mut Report<'_>, name: &str, relays: &RelayList, trust: &Trust) {
    let at = Relay { host: name.to_string(), port: relays.primary().port };
    let proxy = podssh_ws::dial::ProxyChoice::FromEnvironment;
    let ctx = MintContext { relay: &at, trust, ctx: &podssh_relay::context::of(&proxy), timeout: TIMEOUT };
    let token = match token::obtain(&ctx, false).await {
        Ok(token) => token,
        Err(e) => {
            report.fail("token", e.to_string());
            report.unknown("cover credential", "not attempted: there is no relay token");
            return;
        }
    };
    report.ok("token", format!("minted at {name} for the cover check (not shown)"));
    let mut tls = match podssh_ws::client::open_tls(&at.host, at.port, name, trust, &proxy, TIMEOUT).await {
        Ok(tls) => tls,
        Err(e) => {
            report.fail("cover credential", format!("the TLS connection to {name}: {e}"));
            return;
        }
    };
    let subject: [u8; 32] = rand::random();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
        .unwrap_or(i64::MAX);
    let (credential, issuer) =
        match podssh_ws::delegated::request_and_verify(&mut tls, token.secret(), subject, name, now).await {
            Ok(credential) => credential,
            Err(e) => {
                report.fail("cover credential", e.to_string());
                return;
            }
        };
    let exporter = {
        let (_, connection) = tls.get_ref();
        podssh_ws::delegated::client_exporter(connection)
    };
    let Some(exporter) = exporter else {
        report.fail("cover credential", "the connection kept no exporter to check against");
        return;
    };
    let subject_held = credential.subject_key == subject;
    let window_holds = credential.not_before <= now && now <= credential.not_after;
    let named = credential.issuer == name && credential.name == name;
    let bound = credential.exporter.is_some();
    if subject_held && window_holds && named && bound {
        report.ok(
            "cover credential",
            format!(
                "issued by {name} for {name}, subject {}, valid {} to {}, bound to this TLS exporter",
                short(&credential.subject_key),
                credential.not_before,
                credential.not_after
            ),
        );
    } else {
        let why = [
            (!named).then_some(format!("issuer {} name {}", credential.issuer, credential.name)),
            (!subject_held).then_some("another subject key".to_string()),
            (!window_holds).then_some(format!(
                "the window {}..{} does not hold {now}",
                credential.not_before, credential.not_after
            )),
            (!bound).then_some("no exporter binding".to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        report.fail("cover credential", format!("the credential returned is not the one asked for: {why}"));
    }
    refusal(
        report,
        "cover issuer",
        "another issuer",
        podssh_ws::delegated::verify(&credential, "another.example", &issuer, &exporter, now),
        CredentialError::WrongIssuer,
        "the credential was issued by another name",
    );
    refusal(
        report,
        "cover window",
        "a lapsed window",
        podssh_ws::delegated::verify(&credential, name, &issuer, &exporter, credential.not_after.saturating_add(1)),
        CredentialError::Expired,
        "the credential is expired",
    );
    refusal(
        report,
        "cover exporter",
        "another exporter",
        podssh_ws::delegated::verify(&credential, name, &issuer, b"another connection", now),
        CredentialError::WrongBinding,
        "the credential is bound to another exporter",
    );
}

/// The first eight bytes of `key`, in hexadecimal: enough to name the
/// subject in a report, not enough to use it.
fn short(key: &[u8; 32]) -> String {
    key[..8].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `outcome` must be the refusal `want`, whose text is `text`: the line is
/// `ok` with that text, or `FAIL` with what the verifier did instead.
fn refusal(
    report: &mut Report<'_>,
    line: &str,
    what: &str,
    outcome: Result<(), CredentialError>,
    want: CredentialError,
    text: &str,
) {
    match outcome {
        Err(error) if error == want => report.ok(line, format!("{what} is refused: {text}")),
        Err(error) => report.fail(line, format!("{what} was refused, but as {error:?}, not {want:?}")),
        Ok(()) => report.fail(line, format!("{what} was accepted: the verifier did not refuse it")),
    }
}
