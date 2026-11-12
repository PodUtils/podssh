//! Server-sent events as smee.io writes them (`lib/server.js` of
//! probot/smee.io): `id: N`, an `event: NAME` line for its own `ready` and
//! `ping`, and one `data: JSON` line, then a blank line. Sans-IO: bytes go
//! in as they come off the stream, in pieces of any size, and whole events
//! come out. The reading follows the standard's (WHATWG HTML, "Parsing an
//! event stream") for the lines that smee.io writes and the ones that a
//! proxy may add: a line ends with LF, CRLF or CR, a comment begins with a
//! colon, and data lines join with LF.

/// The most bytes that one event may hold before its blank line: the
/// largest frame in base64 inside smee.io's JSON with its headers, twice
/// over, so that a stranger's flood ends the stream rather than the memory.
pub const EVENT_MAX: usize = 2 << 20;

/// One event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Its `event:` field; `message` when it had none, as each POST's has.
    pub name: String,
    /// Its `data:` lines, joined with LF.
    pub data: String,
}

/// The decoder of one stream.
#[derive(Debug, Default)]
pub struct Decoder {
    /// The bytes of a line that has not ended.
    line: Vec<u8>,
    /// A CR ended the last line: an LF right after it ends nothing more.
    after_cr: bool,
    name: Option<String>,
    data: Option<String>,
    /// The bytes of the event so far, against [`EVENT_MAX`].
    size: usize,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Take `bytes`, and give each event that they end; an error when an
    /// event outgrows [`EVENT_MAX`] or a line is not UTF-8, which ends the
    /// stream.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Event>, String> {
        let mut out = Vec::new();
        for &byte in bytes {
            match byte {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = byte == b'\r';
                    let line = std::mem::take(&mut self.line);
                    if let Some(event) = self.line_ended(&line)? {
                        out.push(event);
                    }
                }
                _ => {
                    self.after_cr = false;
                    self.size += 1;
                    if self.size > EVENT_MAX {
                        return Err(format!("an event of more than {} KiB", EVENT_MAX >> 10));
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(out)
    }

    fn line_ended(&mut self, line: &[u8]) -> Result<Option<Event>, String> {
        if line.is_empty() {
            self.size = 0;
            let name = self.name.take();
            // A blank line with no data dispatches nothing (the standard's).
            return Ok(self.data.take().map(|data| Event { name: name.unwrap_or_else(|| "message".into()), data }));
        }
        let line = std::str::from_utf8(line).map_err(|_| "a line of the stream that is not UTF-8".to_string())?;
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => self.name = Some(value.to_string()),
            "data" => match &mut self.data {
                Some(data) => {
                    data.push('\n');
                    data.push_str(value);
                }
                None => self.data = Some(value.to_string()),
            },
            // `id` and `retry` change nothing here: the road never asks for a
            // replay (smee.io keeps none), and opens its own streams.
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes of a stream as `lib/server.js` writes them: `sseReady`, a
    /// POST's `sse` with no event name, and `ssePing`.
    const STREAM: &str = "id: 0\nevent: ready\ndata: {}\n\nid: 1\ndata: {\"host\":\"smee.io\",\"body\":{\"n\":0}}\n\n\
                          id: 2\nevent: ping\ndata: {}\n\n";

    fn names_and_data(events: &[Event]) -> Vec<(&str, &str)> {
        events.iter().map(|e| (e.name.as_str(), e.data.as_str())).collect()
    }

    #[test]
    fn smee_s_own_stream_gives_ready_a_message_and_ping() {
        let events = Decoder::new().feed(STREAM.as_bytes()).unwrap();
        let want = [("ready", "{}"), ("message", "{\"host\":\"smee.io\",\"body\":{\"n\":0}}"), ("ping", "{}")];
        assert_eq!(names_and_data(&events), want);
    }

    #[test]
    fn the_same_events_come_from_pieces_of_each_size_and_each_line_ending() {
        let whole = Decoder::new().feed(STREAM.as_bytes()).unwrap();
        for size in [1, 2, 3, 7, 64] {
            let mut decoder = Decoder::new();
            let mut events = Vec::new();
            for piece in STREAM.as_bytes().chunks(size) {
                events.extend(decoder.feed(piece).unwrap());
            }
            assert_eq!(events, whole, "pieces of {size}");
        }
        for ending in ["\r\n", "\r"] {
            let other = STREAM.replace('\n', ending);
            assert_eq!(Decoder::new().feed(other.as_bytes()).unwrap(), whole, "{ending:?}");
        }
    }

    #[test]
    fn comments_are_passed_over_data_lines_join_and_a_blank_line_alone_gives_nothing() {
        let events = Decoder::new().feed(b": a proxy's comment\n\ndata:a\ndata: b\nretry: 5\n\n").unwrap();
        assert_eq!(names_and_data(&events), [("message", "a\nb")]);
        assert!(Decoder::new().feed(b"id: 4\n\n").unwrap().is_empty());
    }

    #[test]
    fn an_event_past_its_bound_or_not_utf8_ends_the_stream() {
        let mut decoder = Decoder::new();
        let big = vec![b'a'; EVENT_MAX + 1];
        assert!(decoder.feed(b"data: ").is_ok());
        assert!(decoder.feed(&big).unwrap_err().contains("KiB"));
        assert!(Decoder::new().feed(b"data: \xff\n\n").is_err());
    }
}
