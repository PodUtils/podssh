//! The name of a node's tunnel, in the text that the service writes on the
//! session's channel: localhost.run's line `NAME tunneled with tls
//! termination, https://NAME` (its landing page's sample, read 2026-11-10),
//! after a welcome whose lines name other hosts (its admin portal, its
//! documents), and before a line for each request that the tunnel carries
//! (`GET / 200 12ms`). So the name is taken from a line that holds the
//! word's marker alone, never from the first address of the text, and the
//! text is read line by line for as long as the session lives: a free
//! domain "changes after a few hours" (its FAQ), and a later line of the
//! marker names the new one (Inferred: the documents do not say whether
//! the same session says it). A host of the service's own is passed over.

use super::Word;
use crate::pinggy::urls;

/// The longest line kept while no end of line came: a longer one is read
/// in pieces of this size, so that a server that never ends a line holds
/// no more than this.
pub const MOST_LINE: usize = 4096;

/// The tunnel's name of `line`, when it holds `word`'s marker: the host of
/// its first address that is not one of `own`, else its first word that is
/// a DNS name and not one of `own`, as `NAME tunneled ...` begins. A name
/// of an IP address is none.
pub fn of_line(line: &str, word: &Word, own: &dyn Fn(&str) -> bool) -> Option<String> {
    if !line.to_ascii_lowercase().contains(word.marker) {
        return None;
    }
    let addressed = urls::in_text(line).iter().filter_map(|address| urls::host_of(address)).find(|host| !own(host));
    addressed.or_else(|| {
        let first = line.split_whitespace().next()?;
        let first = first.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        urls::host_of(first).filter(|host| !own(host))
    })
}

/// The text of a channel, cut into its lines as it comes.
#[derive(Debug, Default)]
pub struct Lines {
    pending: Vec<u8>,
}

impl Lines {
    /// The lines that `bytes` ends, with no end of line; a piece of
    /// [`MOST_LINE`] bytes with no end is a line too.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for &byte in bytes {
            if byte == b'\n' || self.pending.len() >= MOST_LINE {
                out.push(String::from_utf8_lossy(&self.pending).trim_end_matches('\r').to_string());
                self.pending.clear();
            }
            if byte != b'\n' {
                self.pending.push(byte);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_http::LOCALHOST_RUN;

    /// The landing page's sample, as it stands there, after a welcome whose
    /// links are of the shape of localhost.run's (Inferred).
    const SESSION: &str = "\r\n===============================================\r\nWelcome to localhost.run! \r\n\
        Follow your favourite reverse tunnel at [https://twitter.com/localhost_run].\r\n\
        To set up and manage custom domains go to https://admin.localhost.run/\r\n\
        ===============================================\r\n\r\n** your connection id is 7f3a-..., please mention \
        it\r\n   if you send me any bug reports **\r\n\r\na1b2c3d4e5f6.lhr.life tunneled with tls termination, \r\n\
        https://a1b2c3d4e5f6.lhr.life\r\n\r\nGET  /           200  12ms\r\n";

    fn own(host: &str) -> bool {
        host == "localhost.run" || host.ends_with(".localhost.run")
    }

    fn names(text: &str, chunk: usize) -> Vec<String> {
        let mut lines = Lines::default();
        let mut found = Vec::new();
        for piece in text.as_bytes().chunks(chunk) {
            found.extend(lines.push(piece).iter().filter_map(|line| of_line(line, &LOCALHOST_RUN, &own)));
        }
        found
    }

    #[test]
    fn the_name_is_the_one_of_the_line_of_the_marker_and_no_other_host_of_the_text() {
        for chunk in [1, 7, 4096] {
            assert_eq!(names(SESSION, chunk), ["a1b2c3d4e5f6.lhr.life"], "in pieces of {chunk}");
        }
        let one = "x.lhr.life tunneled with tls termination, https://x.lhr.life\n";
        assert_eq!(names(one, 4096), ["x.lhr.life"]);
    }

    #[test]
    fn a_later_line_of_the_marker_names_the_new_name_and_escapes_and_addresses_are_passed_over() {
        let text =
            format!("{SESSION}\u{1b}[32mb2.lhr.life\u{1b}[0m tunneled with tls termination, https://b2.lhr.life\n");
        assert_eq!(names(&text, 3), ["a1b2c3d4e5f6.lhr.life", "b2.lhr.life"]);
        assert!(names("192.0.2.1 tunneled with tls termination, https://192.0.2.1\n", 64).is_empty());
        assert!(names("admin.localhost.run tunneled\n", 64).is_empty(), "the service's own host");
        assert!(names("https://c3.lhr.life\n", 64).is_empty(), "no marker, no name");
    }

    #[test]
    fn a_line_with_no_end_is_cut_at_its_bound() {
        let mut lines = Lines::default();
        let long = vec![b'a'; MOST_LINE * 2 + 5];
        let cut = lines.push(&long);
        assert_eq!(cut.len(), 2);
        assert!(cut.iter().all(|line| line.len() == MOST_LINE));
        assert_eq!(lines.push(b"\n"), ["aaaaa"]);
    }
}
