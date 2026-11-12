//! A stand-in of smee.io's server on the loopback, written from
//! probot/smee.io's `lib/server.js` (read at 922d925, 2025-12-02): `GET
//! /:channel` with `Accept: text/event-stream` and nothing else in it is a
//! stream (`id`, `event: ready`, `data: {}` at once, a `ping` each 30 s);
//! `POST /:channel` takes a JSON object, sends each stream open on the
//! channel then an event whose data is the request's headers with `body`,
//! `query` and `timestamp`, and answers `200` with no body; a channel is 1
//! to 128 characters of `[a-zA-Z0-9-_]`; a body past Fastify's default
//! 1 MiB is refused with `413`. Nothing is kept: a stream gets only what
//! comes after it opened. The interop test runs smee.io's own server in its
//! place (`.github/workflows/smee-interop.yml`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fastify's default `bodyLimit`.
const BODY_LIMIT: usize = 1 << 20;
/// smee.io's ping of each stream.
const PING: Duration = Duration::from_secs(30);

type Streams = Arc<Mutex<HashMap<String, Vec<Sender<String>>>>>;

/// The stand-in, on a port of the loopback; it runs until the test ends.
pub struct StandIn {
    pub port: u16,
}

impl StandIn {
    pub fn start() -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port of the loopback");
        let port = listener.local_addr().unwrap().port();
        let streams: Streams = Arc::default();
        std::thread::spawn(move || {
            for conn in listener.incoming().map_while(Result::ok) {
                let streams = streams.clone();
                std::thread::spawn(move || serve(conn, streams));
            }
        });
        StandIn { port }
    }
}

fn is_channel(name: &str) -> bool {
    (1..=128).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// One connection: requests, one after another, until one is a stream.
fn serve(conn: TcpStream, streams: Streams) {
    let mut reader = BufReader::new(conn.try_clone().expect("the connection"));
    let mut conn = conn;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        let (method, path) = (words.first().cloned().unwrap_or_default(), words.get(1).cloned().unwrap_or_default());
        let channel = path.trim_start_matches('/').to_string();
        let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        if length > BODY_LIMIT {
            let _ = conn.write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            return;
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        if !is_channel(&channel) {
            let _ = conn.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
            continue;
        }
        match method.as_str() {
            "GET" if header("accept").as_deref() == Some("text/event-stream") => {
                return stream(conn, &channel, &streams);
            }
            "GET" => {
                let page = b"<html>the channel's page</html>";
                let head =
                    format!("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n", page.len());
                let _ = conn.write_all(head.as_bytes()).and_then(|()| conn.write_all(page));
            }
            "POST" => {
                let json = header("content-type").is_some_and(|v| v.starts_with("application/json"));
                let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
                let Some(body) = parsed.filter(|v| v.is_object() && json) else {
                    let _ = conn.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
                    continue;
                };
                // The event, as `bus.emit` sends it: the headers, then the rest.
                let mut event = serde_json::Map::new();
                for (name, value) in &headers {
                    event.insert(name.clone(), serde_json::Value::String(value.clone()));
                }
                event.insert("body".into(), body);
                event.insert("query".into(), serde_json::json!({}));
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                event.insert("timestamp".into(), now.into());
                let data = serde_json::Value::Object(event).to_string();
                if let Some(list) = streams.lock().unwrap().get_mut(&channel) {
                    list.retain(|reader| reader.send(data.clone()).is_ok());
                }
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            }
            _ => {
                let _ = conn.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
            }
        }
    }
}

/// A chunk of a body in chunks.
fn chunk(text: &str) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", text.len()).into_bytes();
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// A stream of `channel`, in Node's chunks, as `reply.raw.writeHead` with
/// no length gives.
fn stream(mut conn: TcpStream, channel: &str, streams: &Streams) {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: \
                keep-alive\r\nx-no-compression: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
    if conn.write_all(head.as_bytes()).is_err() {
        return;
    }
    let (tx, rx) = mpsc::channel::<String>();
    streams.lock().unwrap().entry(channel.to_string()).or_default().push(tx);
    let mut id = 0u64;
    let mut write = |event: Option<&str>, data: &str| {
        let name = event.map(|e| format!("event: {e}\n")).unwrap_or_default();
        let text = format!("id: {id}\n{name}data: {data}\n\n");
        id += 1;
        conn.write_all(&chunk(&text))
    };
    if write(Some("ready"), "{}").is_err() {
        return;
    }
    loop {
        let sent = match rx.recv_timeout(PING) {
            Ok(data) => write(None, &data),
            Err(RecvTimeoutError::Timeout) => write(Some("ping"), "{}"),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if sent.is_err() {
            return;
        }
    }
}
