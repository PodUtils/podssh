//! A file host over HTTPS ([`HttpHost`]): each call of [`Host`] is one
//! request on a connection of its own, with `Connection: close`, through
//! the road's dial (TCP through `HTTPS_PROXY`, then TLS with podssh-ws's
//! provider and trust store, HTTP/1.1 alone, as the smee.io road's), so the
//! road never keeps a connection open between two of its turns at the gate
//! ([`super::pace::Gate`]). The requests are [`super::form`]'s, sent with
//! the road's own User-Agent ([`super::USER_AGENT`]).

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::form::{self, Form};
use super::host::{Doing, Host, Refusal, Stored};
use super::USER_AGENT;
use crate::piping::dial::Dial;
use crate::piping::Server;
use crate::session::OsEntropy;

/// The bound of one request, its connection, its body and its answer: a
/// piece of 4 MiB through a slow proxy takes its time, and a host that
/// holds the road longer holds each other turn behind it.
pub const REQUEST_LIMIT: Duration = Duration::from_secs(120);
/// The most bytes of an answer to an upload or a delete: a URL, or a page.
const ANSWER_MOST: usize = 64 * 1024;

/// A file host of `pod-services`, reached by `dial`.
pub struct HttpHost {
    form: Form,
    /// The host of its upload, which the line names and a note carries.
    name: String,
    dial: Dial,
}

impl HttpHost {
    /// The host of `form`; an upload URL that is not `https://HOST/...` is
    /// refused here, before any piece.
    pub fn new(form: Form, dial: Dial) -> Result<HttpHost, String> {
        let (server, _) = place(&form.upload).map_err(|why| format!("{}: {why}", form.id))?;
        Ok(HttpHost { name: server.host, form, dial })
    }

    pub fn form(&self) -> &Form {
        &self.form
    }

    /// One request of `method` to `url` with `headers` and `body`; the
    /// answer's body at most `most` bytes.
    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        most: usize,
    ) -> Result<pod_proxy::http::Response, Refusal> {
        let (server, path) = place(url).map_err(Refusal::Failed)?;
        let id = &self.form.id;
        let asking = async {
            let (mut io, _) = (self.dial)(&server).await.map_err(Refusal::Failed)?;
            let authority = server.authority();
            let answer =
                pod_proxy::http::exchange(&mut io, USER_AGENT, method, &authority, &path, headers, body, most).await;
            let _ = io.shutdown().await;
            answer.map_err(|e| Refusal::Failed(format!("{id}: {e}")))
        };
        match tokio::time::timeout(REQUEST_LIMIT, asking).await {
            Ok(answer) => answer,
            Err(_) => Err(Refusal::Failed(format!("{id}: no answer within {} s", REQUEST_LIMIT.as_secs()))),
        }
    }
}

/// The server and the path of an `https://` URL: the authority as a Piping
/// Server's is read (a name or an address, a port), the path to its
/// fragment. A user, a space or a control character is refused.
pub fn place(url: &str) -> Result<(Server, String), String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| "a URL that is not https://".to_string())?;
    let rest = rest.split('#').next().unwrap_or_default();
    let (authority, path) = match rest.find(['/', '?']) {
        Some(at) if rest[at..].starts_with('/') => (&rest[..at], rest[at..].to_string()),
        Some(at) => (&rest[..at], format!("/{}", &rest[at..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') || path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("a URL with a user, a space or a control character".into());
    }
    let server = Server::parse(&format!("https://{authority}")).map_err(|_| "a URL of no host".to_string())?;
    Ok((server, path))
}

/// The wait that a 429 or a 503 asks for, in its `Retry-After` seconds.
fn busy(answer: &pod_proxy::http::Response) -> Option<Refusal> {
    if answer.status != 429 && answer.status != 503 {
        return None;
    }
    let wait = answer.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok());
    Some(Refusal::Busy(wait.map(Duration::from_secs)))
}

impl Host for HttpHost {
    fn name(&self) -> &str {
        &self.name
    }

    fn most(&self) -> usize {
        self.form.most
    }

    fn per_hour(&self) -> Option<u32> {
        self.form.per_hour
    }

    fn one_person(&self) -> bool {
        self.form.one_person
    }

    fn owns(&self, url: &str) -> bool {
        form::owns(&self.form, url)
    }

    fn upload(&self, sealed: Vec<u8>) -> Doing<'_, Stored> {
        Box::pin(async move {
            let boundary = form::boundary(&mut OsEntropy).map_err(|e| Refusal::Failed(e.to_string()))?;
            let body = form::upload_body(&self.form, &boundary, &sealed);
            let kind = form::content_type(&boundary);
            let headers = [("Content-Type", kind.as_str()), ("Accept", "*/*")];
            let answer = self.request("POST", &self.form.upload, &headers, &body, ANSWER_MOST).await?;
            form::read_answer(&self.form, answer.status, &answer.headers, &answer.body)
        })
    }

    fn fetch<'a>(&'a self, url: &'a str, most: usize) -> Doing<'a, Vec<u8>> {
        Box::pin(async move {
            let at = form::fetch_url(&self.form, url);
            // A note's URL was checked; the URL of the download is too, as a
            // segment of the catalog's is put in it.
            if !self.owns(&at) {
                return Err(Refusal::Failed(format!("{}: a download of another host", self.form.id)));
            }
            let method = if self.form.fetch_post { "POST" } else { "GET" };
            let answer = self.request(method, &at, &[("Accept", "*/*")], &[], most).await?;
            if let Some(refusal) = busy(&answer) {
                return Err(refusal);
            }
            match answer.status {
                200 => Ok(answer.body),
                status => Err(Refusal::Failed(format!("{} answered {status} to a download", self.form.id))),
            }
        })
    }

    fn delete<'a>(&'a self, stored: &'a Stored) -> Doing<'a, ()> {
        Box::pin(async move {
            let boundary = form::boundary(&mut OsEntropy).map_err(|e| Refusal::Failed(e.to_string()))?;
            let Some(body) = form::delete_body(&self.form, &boundary, stored) else { return Ok(()) };
            if !self.owns(&stored.url) {
                return Err(Refusal::Failed(format!("{}: a delete at another host", self.form.id)));
            }
            let kind = form::content_type(&boundary);
            let headers = [("Content-Type", kind.as_str())];
            let answer = self.request("POST", &stored.url, &headers, &body, ANSWER_MOST);
            match answer.await? {
                answer if (200..300).contains(&answer.status) => Ok(()),
                answer => Err(Refusal::Failed(format!("{} answered {} to a delete", self.form.id, answer.status))),
            }
        })
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
