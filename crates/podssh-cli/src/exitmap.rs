//! The fault table of the exit codes as code, and the `2` versus `64` decision.
//!
//! **One read path for the contract.** `docs/cli.md` ("Exit codes")
//! writes the table in prose; a second reader of that table types the number
//! again, and two places holding one number is where a contract stops being a
//! contract. Every condition podssh reports goes through [`code`], and a script
//! that wants the table reads [`TABLE`].
//!
//! # The decision: a usage error is `64`
//!
//! Five documents disagreed and this is the resolution. **READ**:
//!
//! | source | said |
//! | --- | --- |
//! | `docs/cli.md`, "Exit codes" | **64** |
//! | the fault table below, [`TABLE`] | **`Usage` = 64**; **`Config` = 78**
//! (`EX_CONFIG`) since the operator's decision of 2026-10-05 (`docs/decisions.md`) |
//! | the old entries of the command line, the manual and `cp`/`mv` | **2** |
//! | the old entry of `ssh_config` | **2** |
//! | the old entry of `podssh relay` | **2 for "no relay target"** — the `Config` row |
//!
//! **The collision is the whole of the argument, and it is worse than one
//! collision.** An old entry chose `2` because a usage error and a config error must not
//! share a code. That reasoning is right and it is why **`Config` is the row
//! that moves.** `2` is a *shell* status before it is anything else — it is
//! what a bare `test`, a `grep` miss and a `diff` disagreement all return — so
//! `2` as a podssh fault collides with ordinary command output as well as with
//! `Config`. `64` collides with nothing, and it is `EX_USAGE` in the same
//! header that `docs/cli.md`, "Exit codes", already takes podssh's own failures from.
//!
//! **`2` is not a `sysexits.h` value at all.** The table says its
//! values are POSIX `sysexits.h`, and `2` is absent from that header while
//! `EX_CONFIG` — 78 — is in it, for exactly the row `2` was standing in for.
//!
//! **What this file does NOT do.** It does not edit a document and it does
//! not silently flip the binary. The documents that give the codes now agree on
//! 64 (`docs/cli.md`, "Exit codes"), and a change of a code is the operator's
//! decision (`docs/decisions.md`).

use crate::exit_codes::EXIT_USAGE;

/// POSIX `sysexits.h`. **`README`/`sysexits.h` is the authority for these
/// numbers and [`TABLE`] is the authority for which one each condition takes.**
pub mod sysexits {
    /// The base every other `sysexits.h` value is offset from.
    pub const EX_USAGE: i32 = 64;
    /// The input was there and wrong: a passphrase that does not open its
    /// key file (`podssh agent add-passphrase`, T-228). pod-core's `Class::Data`
    /// (podcrates v0.84.0).
    pub const EX_DATAERR: i32 = 65;
    /// An input file did not exist or was not readable: a source of `cp`.
    pub const EX_NOINPUT: i32 = 66;
    /// Nothing could answer: the peer is unreachable, or a pair was revoked.
    pub const EX_UNAVAILABLE: i32 = 69;
    /// podssh itself is at fault, or a session was truncated.
    pub const EX_SOFTWARE: i32 = 70;
    /// An output file cannot be created: a destination of `cp`.
    pub const EX_CANTCREAT: i32 = 73;
    /// The output could not be written: a stdout that is full or closed
    /// (T-965). No class of pod-core gives it.
    pub const EX_IOERR: i32 = 74;
    /// A temporary failure: the `--timeout` passed, and a later try can work.
    pub const EX_TEMPFAIL: i32 = 75;
    /// The peer refused podssh's credentials, or the pair expired.
    pub const EX_NOPERM: i32 = 77;
    /// The machine is not set up the way this mode needs.
    pub const EX_CONFIG: i32 = 78;
}

// The classes of failure that podcrates shares (T-820): a fault takes its
// class's code where that is the code podssh documents.
use pod_core::failure::Class;

/// Where a fault's exit code comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// `Class::exit_code()` of pod-core, which is podssh's documented code too.
    Pod(Class),
    /// podssh's documented code, kept where pod-core's nearest class gives
    /// another (or where no class of pod-core has this meaning). The manual's
    /// EXIT STATUS wins: a script reads those numbers.
    Own { code: i32, nearest: Option<Class> },
}

/// One row of the fault table.
///
/// **`Fault` carries a reason and not a number**, so a fault cannot exist
/// without a name: [`Fault::name`] gives one for each variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// Bad flags, an unknown verb, a missing host. `docs/cli.md`, "Exit codes".
    Usage,
    /// TCP, TLS, the WebSocket upgrade, or a pre-`101` HTTP status; for
    /// `cp` also an SSH server that cannot be reached, or has neither SFTP
    /// nor a copy by exec.
    RelayUnreachable,
    /// Relay `403`/`401`, or SSH authentication refused; for `cp` also a
    /// host key that podssh did not accept.
    Auth,
    /// A probe returned `????` and the mode needed it.
    Capability,
    /// Relay close `1003`/`1008`/`1009`/`1011`/`1013`, or a framing fault;
    /// for `cp` also a copy whose digests differ, or a session that broke.
    SessionFault,
    /// A source of `cp` is missing or cannot be read.
    NoInput,
    /// A destination of `cp` cannot be written.
    CantCreate,
    /// The `--timeout` passed before the command ended.
    TimedOut,
    /// Relay close `1001`, reason `operator stopped reverse relay`.
    Revoked,
    /// Relay close `1001`, reason `pair expired`.
    PairExpired,
    /// An unparseable config file, or no relay target.
    Config,
    /// The remote command ran and delivered a status.
    Remote(u32),
    /// **The session ran and then ended without a delivered `exit-status`.**
    ///
    /// **This is NOT "a clean close", and the correction is load-bearing.**
    /// The old exit-code table calls this row `ChannelClosed` and describes it as *"a
    /// clean close with none"*, then two paragraphs later says a
    /// `ChannelClosed` that never saw `exit-status` **and never reached a
    /// clean `1000`** is a truncation and exits **70**.
    ///
    /// **Those two sentences cannot both hold, because a `ChannelClosed`
    /// whose close was clean is by definition a `1000`, so every
    /// `ChannelClosed` would satisfy the second clause and `EX_SOFTWARE` would
    /// be the only code it ever takes.** The row is split here instead, so
    /// each clause governs exactly the case it describes:
    /// `ChannelClosed` is the clean `1000` with no status, and
    /// `SessionFault` is the truncated tail.
    ChannelClosed,
}

impl Fault {
    /// The process exit code for this fault. **A delivered `Remote(0)` is
    /// the only value that legitimately returns `0`, and it returns it because
    /// the remote said so.**
    pub fn code(self) -> i32 {
        match self.origin() {
            Origin::Pod(class) => i32::from(class.exit_code()),
            Origin::Own { code, .. } => code,
        }
    }

    /// pod-core's class of this fault, by its meaning; `None` where pod-core
    /// has none (a destination that cannot be written, a remote status).
    pub fn class(self) -> Option<Class> {
        match self.origin() {
            Origin::Pod(class) => Some(class),
            Origin::Own { nearest, .. } => nearest,
        }
    }

    /// Where this fault's code comes from. The class is chosen by meaning,
    /// never by its number, so that a difference stays visible.
    pub fn origin(self) -> Origin {
        let own = |code: i32, nearest: Option<Class>| Origin::Own { code, nearest };
        match self {
            // 64: the value of a usage error in `docs/cli.md` ("Exit codes"), and the one
            // the exit-code table gave `Usage`. See the module header for why `2`
            // lost and why `Config` is the row that moves instead.
            Fault::Usage => Origin::Pod(Class::Usage),
            // 69: there is no relay to talk to.
            Fault::RelayUnreachable => Origin::Pod(Class::Unavailable),
            // 77: the peer refused us. The two `1001` rows land apart from
            // each other because the REASON decides, not the code. An expired
            // pair is refused: a new pair works.
            Fault::Auth | Fault::PairExpired => Origin::Pod(Class::Refused),
            Fault::NoInput => Origin::Pod(Class::NotFound),
            Fault::TimedOut => Origin::Pod(Class::Timeout),
            // 78: this machine is not set up for this mode. See SHARED_CODES.
            Fault::Config => Origin::Pod(Class::Config),
            // Kept 78 (SHARED_CODES with `Config`): pod-core's `Unsupported` is 80.
            Fault::Capability => own(sysexits::EX_CONFIG, Some(Class::Unsupported)),
            // Kept 69: a stopped pair shares `RelayUnreachable`'s code on
            // purpose (SHARED_CODES), and `Fault::name` names which; pod-core's
            // `Revoked` is 78.
            Fault::Revoked => own(sysexits::EX_UNAVAILABLE, Some(Class::Revoked)),
            // 70: a session cut short is pod-core's `Internal` (v0.83.0, COORD-142).
            Fault::SessionFault | Fault::ChannelClosed => Origin::Pod(Class::Internal),
            // 73: an output that cannot be created (v0.83.0, COORD-142).
            Fault::CantCreate => Origin::Pod(Class::CantCreate),
            Fault::Remote(status) => own(status as i32, None),
        }
    }

    /// The fault's name, as `SHARED_CODES` lists it. **No variant returns an empty string**,
    /// so a fault with nothing to say is unrepresentable.
    pub fn name(self) -> &'static str {
        match self {
            Fault::Usage => "Usage",
            Fault::RelayUnreachable => "RelayUnreachable",
            Fault::Auth => "Auth",
            Fault::Capability => "Capability",
            Fault::SessionFault => "SessionFault",
            Fault::NoInput => "NoInput",
            Fault::CantCreate => "CantCreate",
            Fault::TimedOut => "TimedOut",
            Fault::Revoked => "Revoked",
            Fault::PairExpired => "PairExpired",
            Fault::Config => "Config",
            Fault::Remote(_) => "Remote",
            Fault::ChannelClosed => "ChannelClosed",
        }
    }

    /// Whether this fault's MEANING depends on whether the session reached
    /// `ready`, rather than on the close code. **This is the predicate the exit-code rule
    /// *"does the close code alone decide? No — `established` decides first"*
    /// needs**, and it is deliberately **not** implemented as a code match:
    /// a `1000` before `ready` is a session that never existed and a `1000`
    /// after it is a session that ended without a status, **the close code is
    /// the same number in both rows**, and **a function that could tell them
    /// apart by inspecting the code would be the bug this entry is about.**
    pub fn established_sensitive(self) -> bool {
        matches!(self, Fault::SessionFault | Fault::ChannelClosed)
    }

    /// **The close-code decision, and it is the sibling's defect restated as
    /// a function.** The sibling reads the code and assigns no `rc`
    /// (`dropssh` `src/connect.c:455-461`), so a `1009` returns 0.
    ///
    /// **The two `1000` rows are the load-bearing ones** and they are why
    /// this takes `established`: the exit-code rule, *"Does the close code alone decide? No
    /// — `established` decides first"* — *"A `1000` before `established` is a
    /// failed session and a `1009` after it is a truncated one. Both are
    /// faults."*
    pub fn from_close(code: u16, reason: &str, established: bool) -> Fault {
        match code {
            // Parse the REASON, not the code. The relay's table "Reverse close codes" gives two
            // `1001` reasons that demand opposite actions: re-pair, or accept
            // that the pair is gone. The code alone cannot tell them apart.
            1001 => {
                if reason.contains("expired") {
                    Fault::PairExpired
                } else {
                    Fault::Revoked
                }
            }
            1003 | 1008 | 1009 | 1011 | 1013 => Fault::SessionFault,
            // A clean close, before or after `ready`, is a session that did
            // not work. It is NOT the truncation row: the relay reported a
            // normal closure and the session really did end. What is missing
            // is podssh's own remote status, and that is reported on stderr
            // rather than folded into the exit code.
            1000 if !established => Fault::SessionFault,
            _ => Fault::ChannelClosed,
        }
    }
}

/// The exit code for a fault. **The one read path**, so a second constant
/// cannot be typed somewhere else and drift.
pub fn code(fault: Fault) -> i32 {
    fault.code()
}

/// **The table, as data.** This is what the checks below read, and what code
/// reads instead of parsing prose. `Remote` is absent
/// because its value is whatever the remote said.
pub const TABLE: &[(Fault, i32)] = &[
    (Fault::Usage, sysexits::EX_USAGE),
    (Fault::RelayUnreachable, sysexits::EX_UNAVAILABLE),
    (Fault::Auth, sysexits::EX_NOPERM),
    (Fault::Capability, sysexits::EX_CONFIG),
    (Fault::SessionFault, sysexits::EX_SOFTWARE),
    (Fault::Revoked, sysexits::EX_UNAVAILABLE),
    (Fault::PairExpired, sysexits::EX_NOPERM),
    (Fault::Config, sysexits::EX_CONFIG),
    (Fault::ChannelClosed, sysexits::EX_SOFTWARE),
    (Fault::NoInput, sysexits::EX_NOINPUT),
    (Fault::CantCreate, sysexits::EX_CANTCREAT),
    (Fault::TimedOut, sysexits::EX_TEMPFAIL),
];

/// **Codes deliberately shared, and the reason each one is allowed.** Every
/// other pair must differ. **This list is the guard, not a comment**: a new
/// row that collides with an existing one fails
/// `no_undeclared_code_collisions` until the reason is written here, which is
/// the only way a shared code ever becomes a decision instead of an accident.
pub const SHARED_CODES: &[(i32, &[&str])] = &[
    (sysexits::EX_UNAVAILABLE, &["RelayUnreachable", "Revoked"]),
    (sysexits::EX_NOPERM, &["Auth", "PairExpired"]),
    (sysexits::EX_CONFIG, &["Capability", "Config"]),
    // The one this module's first version had to discover by failing. A
    // session that died and a session that ended cleanly are different facts
    // with the same repair — the session did not deliver what you asked for —
    // so they share `EX_SOFTWARE`, and `Fault` keeps them apart.
    (sysexits::EX_SOFTWARE, &["SessionFault", "ChannelClosed"]),
];
/// **The fork, as a function of what the binary actually does.** Returns
/// `Some((the table's value, what the binary emits))` while the decision on 64 and
/// `exit_codes::EXIT_USAGE` disagree, and `None` once they agree.
///
/// **It reads `EXIT_USAGE` rather than hard-coding 2**, so the moment the
/// operator applies the decision this returns `None` with no edit here.
pub fn usage_fork() -> Option<(i32, i32)> {
    if sysexits::EX_USAGE == EXIT_USAGE {
        None
    } else {
        Some((sysexits::EX_USAGE, EXIT_USAGE))
    }
}

#[cfg(test)]
#[path = "exitmap_tests.rs"]
mod tests;
