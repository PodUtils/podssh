//! The handler's answer to a direct-tcpip channel (T-109), apart from
//! `handler.rs` so that each file stays short; `-R` is `remote_forward.rs`
//! (T-123). Each open, refusal and end is said in the audit log (T-116).

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
                self.trail.forward_refused(&self.who, host, port, refusal.description());
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
            self.trail.forward_refused(&self.who, host, port.into(), &why);
            reply.reject(direct::prohibited(&why)).await;
            return Ok(());
        }
        let Some(slot) = self.forwards.take() else {
            self.trail.forward_refused(&self.who, host, port.into(), direct::FULL);
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let mark = self.trail.forward(&self.who, host, port.into());
        direct::open(channel, host.to_string(), port, reply, slot, session.handle(), mark);
        Ok(())
    }
}
