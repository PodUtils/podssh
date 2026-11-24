//! The handler's answer to a direct-tcpip channel (T-109), apart from
//! `handler.rs` so that each file stays short; `-R` is `remote_forward.rs`
//! (T-123).

use russh::server::{ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelOpenFailure};

use super::super::direct;
use super::Served;

impl Served {
    /// A TCP connection from this host: checked here, dialed on a task of
    /// its own, so the answer to the open comes with the dial's.
    pub(super) async fn direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let port = match direct::check(self.settings.no_forwarding, host, port) {
            Ok(port) => port,
            Err(refusal) => {
                reply.reject(refusal).await;
                return Ok(());
            }
        };
        // The key's own limits (no-port-forwarding, permitopen=).
        let refused = match self.rules() {
            Ok(rules) => rules.forward_refusal(host, port),
            Err(why) => Some(why),
        };
        if let Some(why) = refused {
            self.settings.say(&format!("key {}: refused: {why}", self.who));
            reply.reject(direct::prohibited(&why)).await;
            return Ok(());
        }
        let Some(slot) = self.forwards.take() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        direct::open(channel, host.to_string(), port, reply, slot, session.handle());
        Ok(())
    }
}
