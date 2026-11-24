//! The logins of one connection (T-107, T-114, T-774, T-837), apart from
//! the handler so that each file stays short; each said in the audit log
//! (T-116), with the key's fingerprint and why a refusal refused.

use std::sync::Arc;

use russh::keys::{Algorithm, PublicKey};
use russh::server::{Auth, PublicKeyOffer, VerifiedPublicKey};

use super::Served;
use crate::server::audit::Verdict;
use crate::server::authorized::Admission;
use crate::server::rules::Context;
use crate::server::Rules;

/// The audit log's words for a key that no line lists.
const UNLISTED: &str = "not an authorized key";

/// The audit log's words for a connection that a reload or a policy ended.
const ENDED: &str = "the connection was ended";

impl Served {
    /// The rules under which `key` logs in now, or why not; a key that
    /// lines name and refuse is said with each line's reason, as the client
    /// hears only "Permission denied".
    pub(super) fn admit(&self, key: &PublicKey) -> Result<Arc<Rules>, String> {
        match self.authorized.admit(key, &Context::now(self.settings.peer)) {
            Admission::Admitted(rules) => Ok(rules),
            Admission::Unlisted => Err(UNLISTED.to_string()),
            Admission::Refused(reasons) => {
                let who = crate::known_hosts::fingerprint(key);
                for why in &reasons {
                    self.settings.say(&format!("key {who} refused: {why}"));
                }
                Err(reasons.join("; "))
            }
        }
    }

    /// A key offered before the client signs: one that is not listed, or
    /// that its lines refuse now (from=, expiry-time=), is refused; so is
    /// each key of a connection that a client policy ended (T-838).
    pub(super) fn offered(&self, user: &str, offer: PublicKeyOffer<'_>) -> Auth {
        if self.conn.ended().is_some() {
            return Auth::reject();
        }
        if self.control.live.shares.find(user).is_some() {
            return Auth::Accept;
        }
        match self.admit(offer.public_key) {
            Ok(_) => Auth::Accept,
            Err(why) => {
                let who = crate::known_hosts::fingerprint(offer.public_key);
                self.trail.auth(Verdict::Refused, user, Some(&who), "publickey", Some(&why));
                Auth::reject()
            }
        }
    }

    /// A key whose signature russh verified. The login name selects
    /// nothing but a shared shell's name (T-837), which lets any key attach
    /// under its right; a name that the table lacks falls to the keys, as a
    /// wrong key does. Else the key decides, and its line's rules hold for
    /// the whole connection. A security key's signature must carry the
    /// flags that its line asks for (T-774), as sshd checks them: the line
    /// that admitted the key decides, and no later line is tried. The key
    /// is in the server's table before it is checked (T-842): a reload then
    /// either comes first and refuses it here, or finds it.
    pub(super) fn verified(&mut self, user: &str, key: VerifiedPublicKey<'_>) -> Auth {
        let who = crate::known_hosts::fingerprint(key.public_key);
        if self.conn.ended().is_some() {
            self.trail.auth(Verdict::Refused, user, Some(&who), "publickey", Some(ENDED));
            return Auth::reject();
        }
        // Out of the table's logins: a reload of the keys never ends it.
        if let Some(pass) = self.control.live.shares.find(user) {
            self.settings.say(&format!("key {who}: logged in to a shared shell, {}", pass.mode.says()));
            self.trail.auth(Verdict::Accepted, user, Some(&who), "share", None);
            self.who = who;
            self.viewer = Some(pass);
            self.conn.accept();
            return Auth::Accept;
        }
        self.conn.log_in(key.public_key);
        let rules = match self.admit(key.public_key) {
            Ok(rules) => rules,
            Err(why) => {
                self.trail.auth(Verdict::Refused, user, Some(&who), "publickey", Some(&why));
                self.conn.log_out();
                return Auth::reject();
            }
        };
        let sk = matches!(key.public_key.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256);
        if let Some(why) = rules.sk_refusal(sk, key.sk_flags) {
            self.settings.say(&format!("key {who} refused: {why}"));
            self.trail.auth(Verdict::Refused, user, Some(&who), "publickey", Some(&why));
            self.conn.log_out();
            return Auth::reject();
        }
        self.trail.auth(Verdict::Accepted, user, Some(&who), "publickey", None);
        self.log_in(rules, who);
        Auth::Accept
    }

    /// The login of a key under `rules`: its expiry timer where asked, and
    /// the connection accepted in the server's table.
    fn log_in(&mut self, rules: Arc<Rules>, who: String) {
        if let Some(expiry) = rules.expiry.filter(|_| self.settings.revoke_ends_sessions) {
            self.expiry = Some(crate::server::live::end_at_expiry(&self.conn, expiry, self.settings.clone()));
        }
        self.rules = Some(rules);
        self.who = who;
        self.conn.accept();
    }
}
