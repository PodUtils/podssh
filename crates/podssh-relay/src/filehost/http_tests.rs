//! The HTTP host against an in-process stand-in of a file host, reached
//! through the road's dial over an in-memory pipe (no socket, no listener):
//! the stand-in reads each request as a host's server would, keeps each
//! upload's file part, answers its URL as text or JSON with a token where
//! its form deletes, serves a download by GET, by POST or under a segment,
//! takes a delete by its token, and answers 429 when told. The tests read
//! each request's bytes, so that a header or a field that the road sends
//! wrong is seen here and not first at a host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::filehost::form::{Answer, Delete};
use crate::piping::dial::{BoxIo, Dialing, Proto};

/// What the stand-in keeps and saw.
#[derive(Default)]
struct Kept {
    files: HashMap<String, Vec<u8>>,
    next: u64,
    /// Each request's head, as it came.
    heads: Vec<String>,
    /// Each upload's whole body.
    bodies: Vec<Vec<u8>>,
    deleted: Vec<String>,
    /// Answer 429 to this many uploads first.
    busy: usize,
}

#[derive(Clone)]
struct StandIn {
    form: Form,
    kept: Arc<Mutex<Kept>>,
}

impl StandIn {
    fn new(form: Form) -> StandIn {
        StandIn { form, kept: Arc::new(Mutex::new(Kept::default())) }
    }

    fn kept(&self) -> std::sync::MutexGuard<'_, Kept> {
        self.kept.lock().unwrap()
    }

    /// The dial of the road, to this stand-in whatever the server.
    fn dial(&self) -> Dial {
        let me = self.clone();
        Arc::new(move |_: &Server| -> Dialing {
            let me = me.clone();
            Box::pin(async move {
                let (ours, far) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move { me.serve(far).await });
                Ok((Box::new(ours) as BoxIo, Proto::H1))
            })
        })
    }

    /// One request, one answer, then the end of the connection.
    async fn serve(&self, mut io: DuplexStream) {
        let mut buf = Vec::new();
        let end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 4096];
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let length = head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buf[end..].to_vec();
        while body.len() < length {
            let mut chunk = vec![0u8; 64 * 1024];
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        let answer = self.answer(&head, &body);
        let _ = io.write_all(&answer).await;
        let _ = io.shutdown().await;
    }

    fn answer(&self, head: &str, body: &[u8]) -> Vec<u8> {
        let mut words = head.split_whitespace();
        let (method, path) = (words.next().unwrap_or_default(), words.next().unwrap_or_default().to_string());
        let host = self.form.serves[0].clone();
        let mut kept = self.kept();
        kept.heads.push(head.to_string());
        let upload_path = place(&self.form.upload).unwrap().1;
        if method == "POST" && path == upload_path {
            kept.bodies.push(body.to_vec());
            if kept.busy > 0 {
                kept.busy -= 1;
                return reply("429 Too Many Requests", &[("Retry-After", "120")], b"slow down");
            }
            let Some(file) = file_part(head, body) else { return reply("400 Bad Request", &[], b"no file") };
            kept.next += 1;
            let path = format!("/{}/piece.bin", kept.next);
            kept.files.insert(path.clone(), file);
            let url = format!("https://{host}{path}");
            let token = format!("token-{}", kept.next);
            return match &self.form.answer {
                Answer::Text => reply("200 OK", &[("X-Token", &token)], format!("{url}\n").as_bytes()),
                Answer::Json(_) => {
                    let json = format!(r#"{{"status":"success","data":{{"url":"{url}"}}}}"#);
                    reply("200 OK", &[], json.as_bytes())
                }
            };
        }
        let file = match &self.form.fetch_segment {
            Some(segment) => path.strip_prefix(&format!("/{segment}")).map(str::to_string),
            None => Some(path.clone()),
        };
        let Some(file) = file else { return reply("404 Not Found", &[], b"") };
        let deletes = String::from_utf8_lossy(body).contains("name=\"delete\"");
        match (method, deletes, kept.files.contains_key(&file)) {
            ("POST", true, true) => {
                let want = format!("token-{}", file.trim_start_matches('/').split('/').next().unwrap_or_default());
                if !String::from_utf8_lossy(body).contains(&want) {
                    return reply("403 Forbidden", &[], b"");
                }
                kept.files.remove(&file);
                kept.deleted.push(file);
                reply("200 OK", &[], b"")
            }
            ("GET", false, true) if !self.form.fetch_post => reply("200 OK", &[], &kept.files[&file]),
            ("POST", false, true) if self.form.fetch_post => reply("200 OK", &[], &kept.files[&file]),
            _ => reply("404 Not Found", &[], b"not here"),
        }
    }
}

/// The bytes of the part `piece.bin` of a form whose boundary its head gives.
fn file_part(head: &str, body: &[u8]) -> Option<Vec<u8>> {
    let boundary = head.lines().find_map(|l| l.split_once("boundary=").map(|(_, b)| b.trim().to_string()))?;
    let start = b"filename=\"piece.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n";
    let at = body.windows(start.len()).position(|w| w == start)? + start.len();
    let end = format!("\r\n--{boundary}--\r\n");
    let stop = body.len().checked_sub(end.len()).filter(|e| *e >= at && body.ends_with(end.as_bytes()))?;
    Some(body[at..stop].to_vec())
}

fn reply(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A form like a host that answers text and deletes by token.
fn text_form() -> Form {
    Form {
        id: "text-host".into(),
        upload: "https://up.stand-in.test/".into(),
        field: "file".into(),
        fields: vec![("secret".into(), String::new()), ("expires".into(), "1".into())],
        answer: Answer::Text,
        serves: vec!["up.stand-in.test".into()],
        fetch_segment: None,
        fetch_post: false,
        delete: Delete::TokenForm {
            header: "X-Token".into(),
            token_field: "token".into(),
            delete_field: "delete".into(),
        },
        most: 512 << 20,
        per_hour: None,
        one_person: true,
    }
}

/// A form like a host that answers JSON, serves the file under a segment,
/// and deletes nothing.
fn json_form() -> Form {
    Form {
        id: "json-host".into(),
        upload: "https://json.stand-in.test/api/v1/upload".into(),
        field: "file".into(),
        fields: vec![("expire".into(), "60".into())],
        answer: Answer::Json(vec!["data".into(), "url".into()]),
        serves: vec!["json.stand-in.test".into()],
        fetch_segment: Some("dl".into()),
        fetch_post: false,
        delete: Delete::Never,
        most: 100 << 20,
        per_hour: Some(200),
        one_person: false,
    }
}

fn host(stand_in: &StandIn) -> HttpHost {
    HttpHost::new(stand_in.form.clone(), stand_in.dial()).unwrap()
}

#[tokio::test]
async fn an_upload_is_one_form_with_the_road_s_user_agent_and_comes_back_whole_then_deleted() {
    let stand_in = StandIn::new(text_form());
    let host = host(&stand_in);
    assert_eq!(host.name(), "up.stand-in.test");
    let sealed: Vec<u8> = (0..256 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    let stored = host.upload(sealed.clone()).await.unwrap();
    assert_eq!(stored.url, "https://up.stand-in.test/1/piece.bin");
    assert_eq!(stored.token.as_deref(), Some("token-1"));
    {
        let kept = stand_in.kept();
        let head = &kept.heads[0];
        assert!(head.starts_with("POST / HTTP/1.1\r\nHost: up.stand-in.test\r\n"), "{head}");
        assert!(head.contains(&format!("User-Agent: {USER_AGENT}\r\n")), "{head}");
        assert!(head.contains("Content-Type: multipart/form-data; boundary=podssh"), "{head}");
        assert!(head.contains("Connection: close\r\n"), "one request on each connection: {head}");
        let body = String::from_utf8_lossy(&kept.bodies[0]);
        assert!(body.contains("name=\"secret\"\r\n\r\n\r\n") && body.contains("name=\"expires\"\r\n\r\n1\r\n"));
    }
    assert_eq!(host.fetch(&stored.url, sealed.len()).await.unwrap(), sealed);
    assert!(host.fetch(&stored.url, 1024).await.is_err(), "a body over the most is refused");
    host.delete(&stored).await.unwrap();
    assert_eq!(stand_in.kept().deleted, ["/1/piece.bin"]);
    assert!(stand_in.kept().files.is_empty());
    let gone = host.fetch(&stored.url, sealed.len()).await.unwrap_err();
    assert_eq!(gone, Refusal::Failed("text-host answered 404 to a download".into()));
}

#[tokio::test]
async fn a_json_host_downloads_under_its_segment_and_deletes_nothing() {
    let stand_in = StandIn::new(json_form());
    let host = host(&stand_in);
    let stored = host.upload(b"sealed piece".to_vec()).await.unwrap();
    assert_eq!(stored, Stored { url: "https://json.stand-in.test/1/piece.bin".into(), token: None });
    assert_eq!(host.fetch(&stored.url, 1024).await.unwrap(), b"sealed piece");
    let head = stand_in.kept().heads[1].clone();
    assert!(head.starts_with("GET /dl/1/piece.bin HTTP/1.1\r\n"), "{head}");
    host.delete(&stored).await.unwrap();
    assert_eq!(stand_in.kept().heads.len(), 2, "no request for a host that deletes nothing");
    assert_eq!(host.per_hour(), Some(200));
    assert!(!host.owns("https://elsewhere.test/1/piece.bin"));
}

#[tokio::test]
async fn a_host_whose_download_is_a_post_gets_one() {
    let stand_in = StandIn::new(Form { fetch_post: true, delete: Delete::Never, ..text_form() });
    let host = host(&stand_in);
    let stored = host.upload(b"by post".to_vec()).await.unwrap();
    assert_eq!(host.fetch(&stored.url, 1024).await.unwrap(), b"by post");
    let head = stand_in.kept().heads[1].clone();
    assert!(head.starts_with("POST /1/piece.bin HTTP/1.1\r\n") && head.contains("Content-Length: 0\r\n"), "{head}");
}

#[tokio::test]
async fn a_429_is_busy_with_its_retry_after_and_the_next_upload_goes() {
    let stand_in = StandIn::new(text_form());
    stand_in.kept().busy = 1;
    let host = host(&stand_in);
    assert_eq!(host.upload(b"x".to_vec()).await, Err(Refusal::Busy(Some(Duration::from_secs(120)))));
    assert!(host.upload(b"x".to_vec()).await.is_ok());
}

#[tokio::test]
async fn a_url_of_no_https_host_is_refused_before_a_connection() {
    let bad = Form { upload: "http://up.stand-in.test/".into(), ..text_form() };
    assert!(HttpHost::new(bad, StandIn::new(text_form()).dial()).is_err());
    assert!(place("https://user@up.stand-in.test/").is_err());
    assert!(place("https://up.stand-in.test/a b").is_err());
    let (server, path) = place("https://up.stand-in.test:8443?x=1#frag").unwrap();
    assert_eq!((server.host.as_str(), server.port, path.as_str()), ("up.stand-in.test", 8443, "/?x=1"));
    let stand_in = StandIn::new(text_form());
    let host = host(&stand_in);
    let theirs = Stored { url: "https://elsewhere.test/1/piece.bin".into(), token: Some("t".into()) };
    assert!(host.delete(&theirs).await.is_err(), "a delete at another host");
    assert!(stand_in.kept().heads.is_empty(), "nothing was sent");
}

/// The carrier over the HTTP host and the stand-in board: a piece of 256
/// KiB goes up as one sealed upload, comes back whole, and the host deletes
/// it once read; the host never holds the plaintext.
#[tokio::test]
async fn the_carrier_moves_a_piece_through_the_http_host() {
    use crate::filehost::keys::{Keys, LinkId, Way};
    use crate::filehost::pace::Gate;
    use crate::filehost::standin::{Counter, StandInBoard};
    use crate::filehost::Carrier;
    let stand_in = StandIn::new(text_form());
    let shared: Arc<dyn Host> = Arc::new(host(&stand_in));
    let board: Arc<dyn crate::filehost::Board> = Arc::new(StandInBoard::new(Counter::default()));
    let keys = Arc::new(Keys::from_bytes([3; 32]));
    let say: crate::filehost::Say = Arc::new(|_| {});
    let carrier = |hosts| Carrier::new(keys.clone(), hosts, board.clone(), Gate::default(), say.clone());
    let (client, node) = (carrier(vec![shared.clone()]), carrier(vec![shared]));
    let piece: Vec<u8> = (0..256 * 1024).map(|i| (i % 253) as u8).collect();
    client.send(Way::Up, &LinkId([1; 16]), 0, &piece).await.unwrap();
    let stored: Vec<Vec<u8>> = stand_in.kept().files.values().cloned().collect();
    assert_eq!(stored.len(), 1);
    assert!(!stored[0].windows(64).any(|w| w == &piece[..64]), "no plaintext on the host");
    let got = node.receive(Way::Up, &LinkId([1; 16]), 0, Duration::from_secs(30)).await.unwrap();
    assert_eq!(got, piece);
    assert!(stand_in.kept().files.is_empty(), "deleted once read");
}

fn moved(status: u16, location: &str) -> pod_proxy::http::Response {
    pod_proxy::http::Response {
        status,
        reason: String::new(),
        headers: vec![("location".into(), location.into())],
        body: Vec::new(),
        url: String::new(),
    }
}

/// A download that a host sends elsewhere on itself: a path alone is on
/// the host that sent it; a full URL stays as it is, for `owns` to judge;
/// another status, or no Location, is no redirect.
#[test]
fn a_redirect_of_a_download_is_made_absolute_on_its_host() {
    let from = "https://files.example/dl/abc/piece";
    assert_eq!(
        redirect(&moved(302, "/dl/abc/piece?x=1"), from).as_deref(),
        Some("https://files.example/dl/abc/piece?x=1")
    );
    assert_eq!(redirect(&moved(301, "https://files.example/abc"), from).as_deref(), Some("https://files.example/abc"));
    assert_eq!(redirect(&moved(307, "//elsewhere.example/x"), from).as_deref(), Some("//elsewhere.example/x"));
    assert_eq!(redirect(&moved(200, "/x"), from), None);
    let mut none = moved(302, "");
    none.headers.clear();
    assert_eq!(redirect(&none, from), None);
}
