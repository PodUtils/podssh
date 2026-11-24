//! The far end's word to local echo (T-160): how many of the client's bytes
//! reached the pty, and whether the pty echoes. `podssh serve` sends it as
//! extended data of a code of podssh's own on the session's channel, only
//! after the client asked with `env predict@podssh v1`; a server that does
//! not know the request answers FAILURE, and never sends the code.
//!
//! Each report is [`LEN`] bytes: the version (1), the flags (bit 0: ECHO,
//! bit 1: ICANON; each other bit 0), and the count, a big-endian `u64`. A
//! report comes after each byte of the pty's output that was read before
//! it, so the client judges its guesses against a screen that holds the
//! echo of each counted key.

use std::time::Duration;

/// The `env` request that asks the far end for its reports.
pub const ENV: &str = "predict@podssh";
/// The one value of [`ENV`]: the version of the reports below.
pub const VERSION: &str = "v1";
/// The code of the extended data: in the range that RFC 4250 leaves for
/// private use (0xFE000000 to 0xFFFFFFFF, section 4.4.3), "POD" after 0xFE.
pub const EXT: u32 = 0xFE50_4F44;
/// The length of one report.
pub const LEN: usize = 10;
/// How long the far end lets a key's echo come out of the pty before it
/// counts the key in a report (mosh's 50 ms): a report sooner would judge a
/// guess before its echo, and kill it.
pub const ECHO_WAIT: Duration = Duration::from_millis(50);

const FIRST: u8 = 1;
const ECHO: u8 = 1;
const CANONICAL: u8 = 2;

/// The pty's flags that local echo reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// ECHO: the kernel echoes what it reads.
    pub echo: bool,
    /// ICANON: the kernel reads a line, and edits it.
    pub canonical: bool,
}

impl Flags {
    /// A line read with no echo: a question for a password (getpass, sudo,
    /// ssh, `read -s`). No guess shows then. A program that reads raw keys
    /// turns ECHO off too, and echoes them itself (readline, vim): its keys
    /// may show, once the far end echoed the first of an epoch.
    pub fn hidden(self) -> bool {
        self.canonical && !self.echo
    }
}

/// One report: the count of the client's bytes that reached the pty, and
/// the pty's flags then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub offset: u64,
    pub flags: Flags,
}

/// The bytes of `report`.
pub fn encode(report: Report) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out[0] = FIRST;
    let echo = if report.flags.echo { ECHO } else { 0 };
    let canonical = if report.flags.canonical { CANONICAL } else { 0 };
    out[1] = echo | canonical;
    out[2..].copy_from_slice(&report.offset.to_be_bytes());
    out
}

/// The reports of a stream of extended data, which SSH may cut anywhere.
#[derive(Debug, Default)]
pub struct Reports {
    part: Vec<u8>,
}

impl Reports {
    /// The reports that `bytes` complete. `Err` for bytes that are no
    /// report of this version: local echo then stops, as nothing the far
    /// end says can be read any more.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Report>, String> {
        let mut out = Vec::new();
        for &b in bytes {
            self.part.push(b);
            if self.part.len() < LEN {
                continue;
            }
            let (first, flags) = (self.part[0], self.part[1]);
            if first != FIRST || flags & !(ECHO | CANONICAL) != 0 {
                return Err(format!("a report of local echo that this version cannot read ({first:#04x} {flags:#04x})"));
            }
            let mut count = [0u8; 8];
            count.copy_from_slice(&self.part[2..LEN]);
            let flags = Flags { echo: flags & ECHO != 0, canonical: flags & CANONICAL != 0 };
            out.push(Report { offset: u64::from_be_bytes(count), flags });
            self.part.clear();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each report reads back the same, however SSH cuts the stream; a byte
    /// of another version stops the reading.
    #[test]
    fn a_report_reads_back_across_any_cut_and_another_version_is_refused() {
        let flags = [(true, true), (true, false), (false, true), (false, false)];
        let mut stream = Vec::new();
        let mut sent = Vec::new();
        for (i, (echo, canonical)) in flags.into_iter().enumerate() {
            let report = Report { offset: ((i as u64) << 40) | 7, flags: Flags { echo, canonical } };
            stream.extend_from_slice(&encode(report));
            sent.push(report);
        }
        for cut in 1..=LEN + 1 {
            let mut reports = Reports::default();
            let got: Vec<Report> = stream.chunks(cut).flat_map(|c| reports.feed(c).unwrap()).collect();
            assert_eq!(got, sent, "cut every {cut} bytes");
        }
        let mut bad = encode(sent[0]);
        bad[1] |= 4;
        assert!(Reports::default().feed(&bad).is_err());
        bad[1] = 0;
        bad[0] = 2;
        assert!(Reports::default().feed(&bad).is_err());
        assert!(Flags { echo: false, canonical: true }.hidden());
        assert!(!Flags { echo: false, canonical: false }.hidden(), "readline's keys may show");
    }
}
