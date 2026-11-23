//! The site tree of `relay_serve_cover`: a directory in the temporary
//! directory, with a page, an asset, `robots.txt` and the site's own 404; and
//! the requests of the owner's socket.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The bound of each request in the tests.
pub const LIMIT: Duration = Duration::from_secs(20);

/// A site tree in the temporary directory, removed when the test ends.
pub struct Tree {
    dir: PathBuf,
}

impl Tree {
    pub fn new(tag: &str) -> Tree {
        let dir = std::env::temp_dir().join(format!("podssh-cover-site-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(
            dir.join("index.html"),
            b"<!doctype html>\n<html><head><title>Example</title></head>\n<body><h1>Example</h1></body></html>\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("404.html"),
            b"<!doctype html>\n<html><head><title>Not here</title></head>\n<body><h1>Not here</h1></body></html>\n",
        )
        .unwrap();
        std::fs::write(dir.join("assets/style.css"), b"body { color: #222; }\n").unwrap();
        std::fs::write(dir.join("robots.txt"), b"User-agent: *\nDisallow:\n").unwrap();
        Tree { dir }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One request on the owner's socket.
pub async fn local(socket: &Path, path: &str) -> (u16, String) {
    let mut stream = UnixStream::connect(socket).await.expect("the owner's socket");
    let request = format!("GET {path} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, stream.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, body.to_string())
}

/// One POST on the owner's socket, with `body`.
pub async fn local_post(socket: &Path, path: &str, body: &str) -> (u16, String) {
    let mut stream = UnixStream::connect(socket).await.expect("the owner's socket");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: local\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, stream.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, body.to_string())
}

/// The value of `name` in `head`, if it is there.
pub fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (given, value) = line.split_once(':')?;
        given.eq_ignore_ascii_case(name).then(|| value.trim().to_string())
    })
}
