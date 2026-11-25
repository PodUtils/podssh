//! The requests of the road to a bucket of the S3 API: a PUT, a GET and a
//! DELETE of one object, each signed with Signature Version 4 by
//! `pod_link::s3::sign` (PodUtils/podcrates, tested there against the
//! examples of AWS's documentation), or sent unsigned for a prefix that the
//! bucket lets anyone read. The requests go one at a time on one kept
//! connection (rule 2: one outbound connection, through `HTTPS_PROXY`), made
//! again when the server closes it; each is bounded by [`REQUEST_LIMIT`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pod_link::s3::sign::{self, Credentials, Signing, EMPTY_HASH};
use pod_link::s3::{Endpoint, Style};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::piping::dial::{BoxIo, Dial};
use crate::piping::Server;

/// The bound of one request: its connection, its body and its answer.
pub const REQUEST_LIMIT: Duration = Duration::from_secs(120);
/// The most bytes of an answer that is not an object: an error's XML.
const ERROR_MOST: usize = 64 * 1024;

/// What podssh says it is, in each request.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"), " (bucket carrier)");

/// An answer: its status, the fields that the road reads, its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// `Date` and `Last-Modified`, as the server wrote them.
    pub date: Option<String>,
    pub modified: Option<String>,
    pub body: Vec<u8>,
}

/// One bucket at one endpoint, and the road's one connection to it.
pub struct Bucket {
    endpoint: Endpoint,
    style: Style,
    region: String,
    bucket: String,
    dial: Dial,
    kept: Mutex<Option<BoxIo>>,
}

impl Bucket {
    /// `bucket` at `endpoint`, signed for `region`, each connection made by
    /// `dial` (TLS through the proxy for `https`, TCP for a test's `http`).
    pub fn new(endpoint: Endpoint, style: Style, region: &str, bucket: &str, dial: Dial) -> Bucket {
        let (region, bucket) = (region.to_string(), bucket.to_string());
        Bucket { endpoint, style, region, bucket, dial, kept: Mutex::new(None) }
    }

    /// The bucket and its endpoint, for a line.
    pub fn shown(&self) -> String {
        let scheme = if self.endpoint.secure { "https" } else { "http" };
        format!("{} at {scheme}://{}:{}", self.bucket, self.endpoint.host, self.endpoint.port)
    }

    /// The host that a request names: the endpoint's, or the bucket's name
    /// before it in the virtual-host style.
    fn host(&self) -> String {
        match self.style {
            Style::Path => self.endpoint.host.clone(),
            Style::VirtualHost => format!("{}.{}", self.bucket, self.endpoint.host),
        }
    }

    /// `Host`: the port only when it is not the scheme's.
    fn authority(&self) -> String {
        let host = self.host();
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        let default = if self.endpoint.secure { 443 } else { 80 };
        if self.endpoint.port == default {
            host
        } else {
            format!("{host}:{}", self.endpoint.port)
        }
    }

    /// The path of `key`, not encoded.
    pub fn path(&self, key: &str) -> String {
        match self.style {
            Style::Path => format!("{}/{}/{key}", self.endpoint.base, self.bucket),
            Style::VirtualHost => format!("{}/{key}", self.endpoint.base),
        }
    }

    /// The server that [`Bucket::dial`] reaches.
    fn server(&self) -> Server {
        Server { host: self.host(), port: self.endpoint.port, prefix: String::new() }
    }

    /// One request of `method` on `key`, signed with `key_pair` when one is
    /// given; the body of a 2xx answer at most `most` bytes.
    pub async fn request(
        &self,
        method: &str,
        key: &str,
        key_pair: Option<&Credentials>,
        body: &[u8],
        most: usize,
    ) -> Result<Answer, String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let head = headers(self, method, key, key_pair, body, &sign::amz_date(now));
        let target = sign::uri_encode(&self.path(key), true);
        let fields: Vec<(&str, &str)> = head.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let asking = async {
            // One connection at a time: the lock is held through the
            // request, so the next one waits for this one's answer.
            let mut kept = self.kept.lock().await;
            for fresh in [false, true] {
                let io = match kept.take() {
                    Some(io) if !fresh => io,
                    _ => (self.dial)(&self.server()).await.map(|(io, _)| io)?,
                };
                let most = most.max(ERROR_MOST);
                let authority = self.authority();
                let sent =
                    pod_proxy::http::exchange_keep(io, USER_AGENT, method, &authority, &target, &fields, body, most)
                        .await;
                match sent {
                    Ok((answer, again)) => {
                        *kept = again;
                        return Ok(answer);
                    }
                    // A kept connection that the server closed meanwhile is
                    // made again once; a fresh one that fails is the answer.
                    Err(e) if fresh => {
                        return Err(format!("{method} on {}: {}", self.shown(), podssh_ws::text::said(&e)))
                    }
                    Err(_) => continue,
                }
            }
            Err(format!("{method} on {}: no connection", self.shown()))
        };
        let answer = tokio::time::timeout(REQUEST_LIMIT, asking)
            .await
            .map_err(|_| format!("{method} on {}: no answer within {} s", self.shown(), REQUEST_LIMIT.as_secs()))??;
        Ok(Answer {
            status: answer.status,
            date: answer.header("date").map(str::to_string),
            modified: answer.header("last-modified").map(str::to_string),
            body: answer.body,
        })
    }

    /// Drop the kept connection: the end of the road.
    pub async fn close(&self) {
        if let Some(mut io) = self.kept.lock().await.take() {
            let _ = io.shutdown().await;
        }
    }
}

/// The fields of a request, `Authorization` first when it is signed: the
/// signature covers `Host`, the payload's hash and the date, and the token
/// of a temporary key.
pub fn headers(
    bucket: &Bucket,
    method: &str,
    key: &str,
    key_pair: Option<&Credentials>,
    body: &[u8],
    date: &str,
) -> Vec<(String, String)> {
    let Some(key_pair) = key_pair else {
        // An unsigned read of a public prefix: the server wants no field.
        return Vec::new();
    };
    let hash = if body.is_empty() { EMPTY_HASH.to_string() } else { sign::sha256_hex(body) };
    let authority = bucket.authority();
    let mut signed = vec![
        ("Host".to_string(), authority),
        ("x-amz-content-sha256".to_string(), hash.clone()),
        ("x-amz-date".to_string(), date.to_string()),
    ];
    if let Some(token) = &key_pair.session_token {
        signed.push(("x-amz-security-token".to_string(), token.clone()));
    }
    let path = bucket.path(key);
    let fields: Vec<(&str, &str)> = signed.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let signing = Signing {
        method,
        path: &path,
        query: &[],
        headers: &fields,
        payload_hash: &hash,
        date,
        region: &bucket.region,
    };
    let authorization = sign::authorization(key_pair, &signing);
    // `Host` is the exchange's own line, with the same value.
    let mut out = vec![("Authorization".to_string(), authorization)];
    out.extend(signed.into_iter().filter(|(name, _)| name != "Host"));
    out
}

/// An HTTP date (RFC 9110's IMF-fixdate, `Sun, 06 Nov 1994 08:49:37 GMT`)
/// in seconds since 1970; `None` for another form.
pub fn http_date(text: &str) -> Option<i64> {
    let mut words = text.split_whitespace();
    let (_, day, month, year, time, zone) =
        (words.next()?, words.next()?, words.next()?, words.next()?, words.next()?, words.next()?);
    if zone != "GMT" || words.next().is_some() {
        return None;
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month = MONTHS.iter().position(|m| *m == month)? as u32 + 1;
    let (day, year): (u32, i64) = (day.parse().ok()?, year.parse().ok()?);
    let mut clock = time.split(':').map(|part| part.parse::<i64>().ok());
    let (h, m, s) = (clock.next()??, clock.next()??, clock.next()??);
    if !(1..=31).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some(sign::days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + s)
}

/// The words of an answer that failed: its status and the `Code` of the
/// error's XML, never its whole body.
pub fn refused(what: &str, answer: &Answer) -> String {
    let text = String::from_utf8_lossy(&answer.body);
    let code = text
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| podssh_ws::text::one_line(&code.chars().take(64).collect::<String>()))
        .unwrap_or_default();
    format!("{what}: {} {code}", answer.status).trim_end().to_string()
}
