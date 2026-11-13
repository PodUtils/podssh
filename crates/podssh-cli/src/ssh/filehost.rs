//! The file hosts' road of `podssh ssh node://NAME` (T-738), the last of the
//! last fallbacks of the operator's ruling Q78, after every other road: a
//! hello at the node's door on the road's public MQTT broker, then each
//! piece of a way one sealed upload to a public file host of `pod-services`,
//! its URL a sealed note on the broker (`crate::filehost_road`). It needs
//! the pair here; never with --no-e2e, as the end-to-end channel checks the
//! node's key above it. Before its first link, a line names the broker as a
//! third party, and the carrier names each host before its first upload.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::filehost::{self, Carrier};
use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct FileHostRoads {
    carrier: Arc<Carrier>,
    board: String,
    /// Whether the board's line was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl FileHostRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, with no host or broker, or with --no-e2e
    /// (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<FileHostRoads> {
        if off {
            return None;
        }
        let part = part?;
        let ids = crate::filehost_road::on()?;
        // The hosts' lines of Q78 are the user's to see, as each other third
        // party's line is.
        let say: filehost::Say = {
            let (log, shown) = (log.clone(), shown.to_string());
            Arc::new(move |line: String| log.info(&format!("{shown}: the file-host road: {line}")))
        };
        match crate::filehost_road::built(&ids, &part.name, part.connect_token(), say) {
            Ok(built) => Some(FileHostRoads {
                carrier: built.carrier,
                board: built.board,
                said: AtomicBool::new(false),
                log: log.clone(),
                shown: shown.to_string(),
            }),
            Err(why) => {
                log.verbose(&format!("{shown}: no file-host road: {why}"));
                None
            }
        }
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::FileHost);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the broker.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::filehost_road::board_line(&self.board)));
        }
        self.log.verbose(&format!("{}: the file-host road, its notes at {}", self.shown, self.board));
        filehost::road::dial(&self.carrier).await.map(|link| Road::FileHost(Box::new(link)))
    }
}
