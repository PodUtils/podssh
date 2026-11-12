//! What the road posts, and what it reads back out of an event. smee.io takes
//! a POST whose body is a JSON object (its schema: `type: object`), and sends
//! each reader of the channel an event whose data is the JSON of the
//! request's headers with `body`, `query` and `timestamp` beside them
//! (`lib/server.js`), so the road's words sit in `body`: a hello at a door,
//! `{"hello": "..."}`; a frame of a way, `{"n": N, "d": "BASE64"}`, its
//! number from 0 on each way of each link, and its bytes. smee.io keeps no
//! event and replays none, so a number that is not the next one says that a
//! reader missed a frame, or that two POSTs passed each other, and ends the
//! link; the resumable layer sends again what the far end did not get.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

/// The most bytes of one frame, before base64: a POST of a third more,
/// within the 1 MiB that Fastify takes by default (Inferred from its
/// documents; T-741's live run measures smee.io's own bound). A POST that
/// smee.io refuses as too large (413) halves it for the next link.
pub const FRAME_MAX: usize = 256 * 1024;
/// The least that a refusal halves it to.
pub const FRAME_MIN: usize = 4 * 1024;

/// What the body of one event of the road holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A client's hello at a door: its line.
    Hello(String),
    /// A frame of a way: its number and its bytes.
    Frame(u64, Vec<u8>),
}

/// The body of a POST of a hello.
pub fn hello(line: &str) -> String {
    json!({ "hello": line }).to_string()
}

/// The body of a POST of frame `n` of `bytes`.
pub fn frame(n: u64, bytes: &[u8]) -> String {
    json!({ "n": n, "d": STANDARD.encode(bytes) }).to_string()
}

/// The road's message in the data of an event of a POST; an error for data
/// that holds none, a stranger's or a damaged one.
pub fn read(data: &str) -> Result<Message, String> {
    let value: Value = serde_json::from_str(data).map_err(|_| "an event whose data is not JSON".to_string())?;
    let body = value.get("body").ok_or("an event with no body: not a POST's")?;
    if let Some(line) = body.get("hello").and_then(Value::as_str) {
        return Ok(Message::Hello(line.to_string()));
    }
    let n = body.get("n").and_then(Value::as_u64).ok_or("an event whose body is not the road's")?;
    let d = body.get("d").and_then(Value::as_str).ok_or("a frame with no bytes")?;
    let bytes = STANDARD.decode(d).map_err(|_| format!("frame {n}: its bytes are not base64"))?;
    if bytes.len() > FRAME_MAX {
        return Err(format!("frame {n} of {} bytes, more than a frame holds", bytes.len()));
    }
    Ok(Message::Frame(n, bytes))
}

/// The next frame's size after a refusal of `size` as too large.
pub fn halved(size: usize) -> usize {
    (size / 2).max(FRAME_MIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event's data as smee.io writes it for a POST of `body`: the
    /// request's headers beside `body`, `query` and `timestamp`.
    fn event_of(body: &str) -> String {
        format!(
            "{{\"host\":\"smee.io\",\"content-type\":\"application/json\",\"user-agent\":\"podssh/1\",\
             \"body\":{body},\"query\":{{}},\"timestamp\":1762900000000}}"
        )
    }

    #[test]
    fn a_frame_and_a_hello_come_back_out_of_smee_s_event() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(read(&event_of(&frame(7, &bytes))), Ok(Message::Frame(7, bytes)));
        assert_eq!(read(&event_of(&frame(0, b""))), Ok(Message::Frame(0, Vec::new())));
        assert_eq!(read(&event_of(&hello("podssh-smee 1 aa bb"))), Ok(Message::Hello("podssh-smee 1 aa bb".into())));
    }

    #[test]
    fn a_frame_is_a_third_larger_than_its_bytes_and_stays_within_fastify_s_bound() {
        let posted = frame(u64::MAX, &vec![0xa5; FRAME_MAX]);
        assert!(posted.len() < FRAME_MAX * 4 / 3 + 64, "{}", posted.len());
        assert!(posted.len() < 1 << 20, "within Fastify's default bodyLimit");
    }

    #[test]
    fn ready_ping_and_a_stranger_s_post_are_no_frame() {
        for data in ["{}", "not json", &event_of("{\"zen\":\"x\"}"), &event_of("{\"n\":1,\"d\":\"***\"}")] {
            assert!(read(data).is_err(), "{data}");
        }
        assert!(read(&event_of("{\"n\":-1,\"d\":\"\"}")).is_err(), "a number is never negative");
    }

    #[test]
    fn a_refusal_halves_a_frame_down_to_its_least() {
        assert_eq!(halved(FRAME_MAX), FRAME_MAX / 2);
        assert_eq!(halved(FRAME_MIN), FRAME_MIN);
        assert_eq!(halved(FRAME_MIN + 1), FRAME_MIN);
    }
}
