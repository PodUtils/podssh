//! HTTP/1.1 to smee.io as the road needs it: a POST of a JSON object, one at
//! a time on one kept connection, and a GET of a channel's stream of events
//! on a connection of its own. So an end holds two connections while a link
//! runs, as the split HTTP road may where a proxy refused the upgrade (Q44),
//! and no request ever waits behind another's body. HTTP/1.1 alone, by
//! ALPN: a stream of events is a body with no end, which HTTP/1.1 carries
//! on its own connection with nothing to tune, and smee.io's Fastify answers
//! it either way. The connection is podssh-ws's: TCP through `HTTPS_PROXY`,
//! TLS with its provider and trust store (`crate::piping::dial`'s way), so
//! a proxy sees the name and nothing else.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use super::sse::{Decoder, Event};
use crate::piping::dial::{BoxIo, Dial, Dialing, Proto, ALPN_H1, CONNECT_LIMIT};
use crate::piping::exchange::Failed;
use crate::piping::http1::{read_head, Framing, Reader};
use crate::piping::Server;

/// The most of an answer's body that a POST reads: smee.io's is empty.
const ANSWER_CAP: usize = 16 * 1024;

/// TLS to each server through `proxy`, verified with `trust`, offering
/// HTTP/1.1 alone.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |server: &Server| -> Dialing {
        let (server, trust, proxy) = (server.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let shown = server.to_string();
            let base = podssh_ws::tls::config_for(&trust).map_err(|e| format!("{shown}: {e}"))?;
            // A caller's own configuration is used as it is (its ALPN, if any).
            let config = if matches!(trust, Trust::Caller(_)) {
                base
            } else {
                let mut config = (*base).clone();
                config.alpn_protocols = vec![ALPN_H1.to_vec()];
                Arc::new(config)
            };
            let name = rustls::pki_types::ServerName::try_from(server.host.clone())
                .map_err(|e| format!("{shown}: {:?} is not a server name: {e}", server.host))?;
            let tcp = podssh_ws::dial::dial(&server.host, server.port, &proxy, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("{shown}: {e}"))?;
            let connector = tokio_rustls::TlsConnector::from(config);
            match tokio::time::timeout(CONNECT_LIMIT, connector.connect(name, tcp)).await {
                Err(_) => Err(format!("{shown}: no TLS within {} s", CONNECT_LIMIT.as_secs())),
                Ok(Err(e)) => Err(format!("{shown}: {}", podssh_ws::tls::handshake_failure(&e))),
                Ok(Ok(tls)) => Ok((Box::new(tls) as BoxIo, Proto::H1)),
            }
        })
    })
}

/// A request's head. `authority` and `path` are the road's own words
/// (`Server::parse`, and channels of `[0-9a-f]`), which hold no space and
/// no line break. The headers are few on purpose: smee.io sends each of a
/// POST's headers to each reader of the channel.
pub fn request(method: &str, authority: &str, path: &str, body: Option<usize>) -> Vec<u8> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n", super::USER_AGENT);
    match body {
        // smee.io serves a stream only to this Accept, and nothing else in it.
        None => head.push_str("Accept: text/event-stream\r\nCache-Control: no-cache\r\n"),
        Some(n) => head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {n}\r\n")),
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// The HTTP client of one server.
pub struct Http {
    server: Server,
    dial: Dial,
    /// The kept connection of the POSTs, with the bytes read past the last
    /// answer: one POST at a time, so that frames keep their order.
    posting: Mutex<Option<(BoxIo, Vec<u8>)>>,
}

impl Http {
    pub fn new(server: Server, dial: Dial) -> Http {
        Http { server, dial, posting: Mutex::new(None) }
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    async fn connect(&self) -> Result<BoxIo, Failed> {
        (self.dial)(&self.server).await.map(|(io, _)| io).map_err(Failed::lost)
    }

    /// POST `json` to `channel`, within `wait`; `Ok` on smee.io's `200`,
    /// which it gives once each reader of the channel was sent the event.
    pub async fn post(&self, channel: &str, json: &str, wait: Duration) -> Result<(), Failed> {
        match tokio::time::timeout(wait, self.post_now(channel, json)).await {
            Ok(done) => done,
            Err(_) => {
                // A connection that a POST left in the middle carries no other.
                *self.posting.lock().await = None;
                Err(Failed::waited(wait))
            }
        }
    }

    async fn post_now(&self, channel: &str, json: &str) -> Result<(), Failed> {
        let mut kept = self.posting.lock().await;
        let mut request = request("POST", &self.server.authority(), &self.server.path(channel), Some(json.len()));
        request.extend_from_slice(json.as_bytes());
        let (mut io, mut buf, reused) = match kept.take() {
            Some((io, buf)) => (io, buf, true),
            None => (self.connect().await?, Vec::new(), false),
        };
        let sent = io.write_all(&request).await.and(io.flush().await);
        let answer = match sent {
            Ok(()) => read_head(&mut io, &mut buf).await,
            Err(e) => Err(e.to_string()),
        };
        let (mut io, mut buf, answer) = match answer {
            Ok(answer) => (io, buf, answer),
            // A kept connection that the server or a proxy closed while it
            // was idle: once more on a new one. A POST that went whole but
            // whose answer was lost comes twice, which the reader's numbers
            // tell, and the link ends there.
            Err(_) if reused => {
                let (mut io, mut buf) = (self.connect().await?, Vec::new());
                io.write_all(&request).await.map_err(|e| Failed::lost(e.to_string()))?;
                let answer = read_head(&mut io, &mut buf).await.map_err(Failed::lost)?;
                (io, buf, answer)
            }
            Err(why) => return Err(Failed::lost(why)),
        };
        let mut reader = Reader::new(&mut io, std::mem::take(&mut buf), answer.framing);
        let text = reader.all(ANSWER_CAP).await.map_err(Failed::lost)?;
        let finished = reader.finished();
        let (_, rest) = reader.into_parts();
        if answer.keep && finished {
            *kept = Some((io, rest));
        }
        match answer.status {
            200..=299 => Ok(()),
            status => Err(Failed::status(status, String::from_utf8_lossy(&text).into_owned())),
        }
    }

    /// The stream of `channel`'s events, once its head came within `wait`.
    pub async fn stream(&self, channel: &str, wait: Duration) -> Result<Events, Failed> {
        let opening = async {
            let mut io = self.connect().await?;
            let request = request("GET", &self.server.authority(), &self.server.path(channel), None);
            io.write_all(&request).await.map_err(|e| Failed::lost(e.to_string()))?;
            let mut buf = Vec::new();
            let answer = read_head(&mut io, &mut buf).await.map_err(Failed::lost)?;
            if answer.status != 200 {
                let mut reader = Reader::new(io, buf, answer.framing);
                let text = reader.all(ANSWER_CAP).await.unwrap_or_default();
                return Err(Failed::status(answer.status, String::from_utf8_lossy(&text).into_owned()));
            }
            if answer.framing == Framing::Length(0) {
                return Err(Failed::lost("a stream of events with no body"));
            }
            Ok(Events { reader: Reader::new(io, buf, answer.framing), decoder: Decoder::new(), queue: VecDeque::new() })
        };
        tokio::time::timeout(wait, opening).await.unwrap_or_else(|_| Err(Failed::waited(wait)))
    }

    /// End the kept connection of the POSTs.
    pub async fn close(&self) {
        if let Some((mut io, _)) = self.posting.lock().await.take() {
            let _ = io.shutdown().await;
        }
    }
}

/// A channel's stream of events, read as they come.
pub struct Events {
    reader: Reader<BoxIo>,
    decoder: Decoder,
    queue: VecDeque<Event>,
}

impl Events {
    /// The next event within `idle`, smee.io's `ping` of each 30 s among
    /// them; `None` at the stream's end. No byte within `idle` is an error:
    /// a stream whose pings stop is held or gone.
    pub async fn next(&mut self, idle: Duration) -> Result<Option<Event>, String> {
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Ok(Some(event));
            }
            let bytes = match tokio::time::timeout(idle, self.reader.next()).await {
                Err(_) => return Err(format!("no event within {} s, not even smee.io's ping", idle.as_secs())),
                Ok(Err(why)) => return Err(why),
                Ok(Ok(None)) => return Ok(None),
                Ok(Ok(Some(bytes))) => bytes,
            };
            self.queue.extend(self.decoder.feed(&bytes)?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_asks_for_events_alone_and_a_post_says_json_and_its_length() {
        let get = String::from_utf8(request("GET", "smee.example", "/abc", None)).unwrap();
        assert!(get.starts_with("GET /abc HTTP/1.1\r\nHost: smee.example\r\n"), "{get}");
        assert!(get.contains("\r\nAccept: text/event-stream\r\n") && get.ends_with("\r\n\r\n"), "{get}");
        let post = String::from_utf8(request("POST", "smee.example:8443", "/p/abc", Some(12))).unwrap();
        assert!(post.contains("Content-Type: application/json\r\nContent-Length: 12\r\n"), "{post}");
        assert!(!post.contains("Accept:"), "{post}");
        assert!(!post.to_ascii_lowercase().contains("cookie"), "nothing of the user goes in a header");
    }
}
