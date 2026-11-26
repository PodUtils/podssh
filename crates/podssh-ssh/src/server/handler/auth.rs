//! The logins of one connection (T-107, T-114, T-774, T-837), apart from
//! the handler so that each file stays short; each said in the audit log
//! (T-116), with the key's fingerprint and why a refusal refused. With
//! `--totp` (T-115), a key that passes gets a partial success, and the
//! one-time code comes by keyboard-interactive, as sshd with PAM asks.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::SystemTime;

use russh::keys::{Algorithm, PublicKey};
use russh::server::{Auth, PublicKeyOffer, Response, VerifiedPublicKey};
use russh::{MethodKind, MethodSet};
use zeroize::Zeroizing;

use super::Served;
use crate::server::audit::Verdict;
use crate::server::authorized::Admission;
use crate::server::rules::Context;
use crate::server::totp::{self, Checked};
use crate::server::Rules;

/// The method of a login with a key and a code, in the audit log.
const BOTH: &str = "publickey,keyboard-interactive";

/// The codes that one key may get wrong on one connection before it must
/// sign again, as sshd's PAM conversation ends after three.
pub const MOST_TRIES: u32 = 3;

/// The one prompt, with no echo.
const PROMPTS: &[(Cow<'static, str>, bool)] = &[(Cow::Borrowed(totp::PROMPT), false)];

/// A key that passed, whose code is still to come; bound to the login
/// name it came with, as RFC 4252 binds a partial success.
pub(super) struct Pending {
    user: String,
    rules: Arc<Rules>,
    who: String,
    tries: u32,
}

fn methods(kind: MethodKind) -> MethodSet {
    MethodSet::from(&[kind][..])
}

/// A refusal that sends the client back to its keys.
fn back_to_keys() -> Auth {
    Auth::Reject { proceed_with_methods: Some(methods(MethodKind::PublicKey)), partial_success: false }
}

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
            // Said too, as the client hears only "Permission denied": a
            // client's line names no key. russh's bound of tries per
            // connection bounds these lines.
            Admission::Unlisted => {
                self.settings.say(&format!("key {} refused: {UNLISTED}", crate::known_hosts::fingerprint(key)));
                Err(UNLISTED.to_string())
            }
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
        // With --totp, the key alone is half: the code comes next.
        if self.settings.totp.is_some() {
            self.trail.auth(Verdict::Partial, user, Some(&who), "publickey", None);
            self.pending = Some(Pending { user: user.to_string(), rules, who, tries: 0 });
            let next = Some(methods(MethodKind::KeyboardInteractive));
            return Auth::Reject { proceed_with_methods: next, partial_success: true };
        }
        self.trail.auth(Verdict::Accepted, user, Some(&who), "publickey", None);
        self.log_in(rules, who);
        Auth::Accept
    }

    /// keyboard-interactive: the prompt of the code, then its check, for a
    /// key that passed under the same login name; for anything else, back
    /// to the keys. The check reads and writes the state under a lock that
    /// another serve may hold, so it runs on a blocking thread.
    pub(super) async fn interactive(&mut self, user: &str, response: Option<Response<'_>>) -> Auth {
        let live = self.conn.ended().is_none();
        let who = self.pending.as_ref().filter(|p| live && p.user == user).map(|p| p.who.clone());
        let (Some(totp), Some(who)) = (self.settings.totp.clone(), who) else {
            self.pending = None;
            return back_to_keys();
        };
        let answer = match response {
            None => {
                let (name, instructions) = (Cow::Borrowed(""), Cow::Borrowed(""));
                return Auth::Partial { name, instructions, prompts: Cow::Borrowed(PROMPTS) };
            }
            Some(mut given) => Zeroizing::new(given.next().map(|b| b.to_vec()).unwrap_or_default()),
        };
        let key = who.clone();
        let judged = tokio::task::spawn_blocking(move || totp.check(&key, &answer, SystemTime::now())).await;
        match judged.map_err(|e| e.to_string()).and_then(|checked| checked) {
            Ok(Checked::Accepted) => {
                let Some(pending) = self.pending.take() else { return back_to_keys() };
                self.trail.auth(Verdict::Accepted, user, Some(&who), BOTH, None);
                self.log_in(pending.rules, pending.who);
                Auth::Accept
            }
            Ok(refused) => self.refuse_code(user, &refused.says(), false),
            // The state cannot be read or written: no code can be judged.
            Err(why) => self.refuse_code(user, &format!("the one-time codes cannot be checked: {why}"), true),
        }
    }

    /// A code refused, said on serve's stderr and in the audit log (never
    /// the code); after [`MOST_TRIES`], or at `last`, back to the keys.
    fn refuse_code(&mut self, user: &str, why: &str, last: bool) -> Auth {
        let Some(pending) = self.pending.as_mut() else { return back_to_keys() };
        pending.tries += 1;
        self.settings.say(&format!("key {}: one-time code refused: {why}", pending.who));
        self.trail.auth(Verdict::Refused, user, Some(&pending.who), BOTH, Some(why));
        if last || pending.tries >= MOST_TRIES {
            self.pending = None;
            self.conn.log_out();
            return back_to_keys();
        }
        Auth::Reject { proceed_with_methods: Some(methods(MethodKind::KeyboardInteractive)), partial_success: true }
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
