//! THE RELAY's items on the HTTP road (T-319), on the WebSocket over HTTP/2
//! (T-321) and on QUIC to the relay role (T-667), apart from `facts.rs` for
//! the length of that file; each number is read from the constant the road
//! uses.

use super::super::model::{Block, Span};

/// The item, after the relay's own.
pub(super) fn blocks() -> Vec<Block> {
    use podssh_relay::http_road::{client, BATCH_MAX, DOWN_MAX, WAIT_MAX};
    use podssh_relay::serve::http_road::sessions;
    let text = format!(
        "For a proxy that ends TLS for the relay's name, refuses the WebSocket upgrade and still carries plain \
         HTTPS requests. When each relay host failed and the way to one of them refused the upgrade (a page of the \
         proxy's, or a 426 of a relay that got the request with its Upgrade taken off), podssh ssh, each command \
         that reaches a server as it does, and podssh proxy carry the session over requests of HTTP/1.1 to that \
         host, which podssh relay serve serves, with the same token, the same targets and the same limits as the \
         WebSocket road. The split form comes first, on two connections, which the operator's ruling Q44 allows on \
         this road alone: the bytes up in numbered batches of {batch} KiB at most, one POST after another, and the \
         bytes down from their offset in a request that waits up to {wait} s; the role holds {window} batches and \
         {down} MiB down that the client has not acknowledged, and an answer down ends a moment after nothing more \
         came, or at {answer} MiB, so that a hop that holds an answer to its end holds a short one. Each request \
         goes again, as it was, until an answer comes, for {retry} s at most: a batch's number and an offset make it \
         one that may come twice. The role names the batch that each answer stores, and the reason of each \
         refusal (full, unknown session, not allowed); the last batch carries the count of the bytes up, and the \
         target's end the count of the bytes down, and a count that differs fails the session. When the second \
         connection does not answer within {limit} s, the serial form \
         follows on the first: one POST after another, each with a batch up when one waits and the bytes down in \
         its answer. A session's id goes in its paths, and its key in a header alone. A close of the road other \
         than 1000 is said by podssh ssh as by podssh proxy: the leg that ended it, with its code and reason, \
         before SSH's own line. The batches and the wait are the road's own, or smaller where podssh doctor \
         --stream measured a cap on bodies or a quiet end on the path to that host (see FILES). The role's \
         /relays.json names these limits in limits.http, which a client that does not know it ignores. podssh \
         doctor's line forward names the road that carried its check: over a WebSocket, or over the HTTP road and \
         its form, one, split or serial, with the road in its --json samples. PODSSH_HTTP_ROAD turns the \
         road off, or names one form. Where the host's /relays.json names a third form, one (podssh relay serve's, \
         over HTTP/1.1 or HTTP/2), it comes first: one POST whose body is the way up and whose answer, after a mark \
         that comes at once, is the way down, on one connection, for a way whose hops pass a body as it comes; a \
         mark that does not come within 2 s means that a hop holds the body, and the split form follows, at once \
         for the rest of the run. The default relay serves no HTTP road.",
        batch = BATCH_MAX / 1024,
        wait = WAIT_MAX.as_secs(),
        window = sessions::WINDOW,
        down = sessions::DOWN_WINDOW >> 20,
        answer = DOWN_MAX >> 20,
        retry = client::RETRY_FOR.as_secs(),
        limit = client::LIMIT.as_secs(),
    );
    vec![Block::Item { term: vec![Span::Lit("The HTTP road".into())], text }, h2_road(), quic_road()]
}

/// The item of QUIC to the relay role.
fn quic_road() -> Block {
    use podssh_relay::quic_road::{dial, HEAD_START, REMEMBERED};
    let text = format!(
        "Where a relay host that you named offers QUIC in its /relays.json (forward.quic, as podssh relay serve \
         --quic yes does), and no proxy is set for it, a session of podssh ssh, of each command that reaches a \
         server as it does, and of podssh proxy races QUIC on UDP before TCP: first one packet of a version that no \
         server speaks to the host's first address of each family at that port, which a server of QUIC answers \
         with its versions within {probe} ms; then QUIC's handshake with the ALPN podssh-relay/1, checked as TLS \
         is for the host's name, and the upgrade of the session on one stream of the connection, with its path and \
         its token, the relay's refusal as on TCP. The TCP road starts {head} ms after QUIC, or at once where QUIC \
         failed; the first session is kept and the other road is closed at once, and a refusal of the relay on \
         either road ends the race. A host whose UDP failed is not tried over QUIC again by that run for {kept} \
         minutes, and one whose QUIC answered is not probed again for as long. A connection keeps itself alive \
         every {keepalive} s and ends after {silence} s with no packet: a lost connection is a lost link, which \
         the resumable layer resumes on any road. -v names the road: over QUIC. PODSSH_QUIC says which hosts \
         race it: by default a host that you named and that offered it; no turns it off.",
        probe = podssh_relay::quick::probe::WAIT.as_millis(),
        head = HEAD_START.as_millis(),
        kept = REMEMBERED.as_secs() / 60,
        keepalive = dial::KEEPALIVE.as_secs(),
        silence = dial::SILENCE.as_secs(),
    );
    Block::Item { term: vec![Span::Lit("QUIC to podssh's relay role".into())], text }
}

/// The item of the WebSocket over HTTP/2.
fn h2_road() -> Block {
    use podssh_ws::h2_road::{CONNECTION_WINDOW, IDLE, REMEMBERED, STREAMS, STREAM_WINDOW};
    let text = format!(
        "Where a relay host offers it, as podssh relay serve does, a session of podssh ssh, of each command that \
         reaches a server as it does, and of podssh proxy is one stream of an HTTP/2 connection (RFC 8441): podssh \
         offers h2, then http/1.1, by ALPN, on a TLS connection of this road alone, and once the server's SETTINGS \
         offer extended CONNECT, it asks for the session with a CONNECT whose :protocol is websocket, with the path, \
         the name and the token of the upgrade, the token in a field that HPACK never indexes; a 200 opens it, and \
         another status is the relay's refusal, as for the upgrade. The sessions of one process share a connection, \
         {streams} at most, each with a window of {stream} MiB in a window of {connection} MiB for the connection; \
         another session opens another connection, and one with no session closes after {idle} s. A lost connection \
         is a lost link for each of its sessions. Where TLS chose http/1.1, the upgrade goes on that connection; \
         where the SETTINGS offer no extended CONNECT, or HTTP/2 did not carry the CONNECT, that connection closes, \
         the upgrade goes on a new one, -v says why, and the run takes HTTP/1.1 to that host for {remembered} \
         minutes. PODSSH_H2 says which hosts take the road: by default a relay host that you named, and no host of \
         the default relay, whose edge offers no extended CONNECT. podssh doctor's line http2 names what a host \
         offers.",
        streams = STREAMS,
        stream = STREAM_WINDOW >> 20,
        connection = CONNECTION_WINDOW >> 20,
        idle = IDLE.as_secs(),
        remembered = REMEMBERED.as_secs() / 60,
    );
    Block::Item { term: vec![Span::Lit("The WebSocket over HTTP/2".into())], text }
}
