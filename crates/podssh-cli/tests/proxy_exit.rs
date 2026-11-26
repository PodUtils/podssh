//! The exit of `podssh proxy` (and each command that takes its map) when no
//! session opened, against the manual's EXIT STATUS: a refusal of the relay
//! is 77, at the mint as at the upgrade (T-940), and so is a relay that
//! issues no tokens (503, T-1009); a relay that cannot be
//! reached, 69; a setting, 78. One table, one rule.

use podssh_cli::proxy::sysexit;
use podssh_relay::open::OpenError;
use podssh_relay::token::TokenError;
use podssh_ws::client::ConnectError;

#[test]
fn a_refusal_of_the_relay_is_77_at_the_mint_and_at_the_upgrade() {
    let failed = |status: u16| OpenError::Token(TokenError::Failed { status, detail: String::new() });
    let refused = |status: u16| {
        OpenError::Token(TokenError::Connect(ConnectError::Refused { status, body: "reverse: forbidden".into() }))
    };
    let rows: Vec<(OpenError, i32, &str)> = vec![
        (failed(403), 77, "a mint of a list of keys refuses this key"),
        (failed(401), 77, "a mint that asked a key and got none"),
        (failed(500), 69, "a mint that failed"),
        (OpenError::Token(TokenError::NotIssued { give: "PODSSH_RELAY_TOKEN".into() }), 77, "a mint of none"),
        (OpenError::Token(TokenError::RateLimited { retry_after: None }), 69, "a brake"),
        (refused(403), 77, "the upgrade refused"),
        (refused(401), 77, "the upgrade refused a token"),
        (OpenError::Token(TokenError::BadEnvironment), 78, "a token that is no token"),
    ];
    for (error, code, why) in rows {
        assert_eq!(sysexit(&error), code, "{why}");
    }
}
