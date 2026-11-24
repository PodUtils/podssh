//! The response codes of TPM 2.0 (part 2, TPM_RC), in words: one line that
//! names the code, says what it means, and which handle, session or
//! parameter it is of. The names are written inside their sentence, as
//! `tpm2_rc_decode` of tpm2-tools prints them, so that a search finds them.

/// The format-one codes (bit 7 set): their number, with 0x080, and words.
const FORMAT_ONE: &[(u32, &str)] = &[
    (0x081, "TPM_RC_ASYMMETRIC: an asymmetric algorithm is not supported or not right"),
    (0x082, "TPM_RC_ATTRIBUTES: the attributes of an object are not right"),
    (0x083, "TPM_RC_HASH: the hash algorithm is not supported or not right"),
    (0x084, "TPM_RC_VALUE: a value is out of range or not right for the context"),
    (0x085, "TPM_RC_HIERARCHY: the hierarchy is not enabled"),
    (0x087, "TPM_RC_KEY_SIZE: the key size is not supported"),
    (0x08A, "TPM_RC_TYPE: the type of the value is not right"),
    (0x08B, "TPM_RC_HANDLE: the handle is not right"),
    (0x08D, "TPM_RC_RANGE: a value is out of range"),
    (0x08E, "TPM_RC_AUTH_FAIL: the authorization failed"),
    (0x08F, "TPM_RC_NONCE: the nonce is not right"),
    (0x092, "TPM_RC_SCHEME: the scheme is not supported"),
    (0x095, "TPM_RC_SIZE: a size is not right"),
    (0x096, "TPM_RC_SYMMETRIC: the symmetric algorithm is not supported"),
    (0x097, "TPM_RC_TAG: a tag is not right"),
    (0x098, "TPM_RC_SELECTOR: a union selector is not right"),
    (0x09A, "TPM_RC_INSUFFICIENT: the input is too short"),
    (0x09B, "TPM_RC_SIGNATURE: the signature is not valid"),
    (0x09C, "TPM_RC_KEY: the key is not right for the command"),
    (0x09D, "TPM_RC_POLICY_FAIL: the policy of the key was not met"),
    (0x09F, "TPM_RC_INTEGRITY: the integrity check of the key failed"),
    (0x0A0, "TPM_RC_TICKET: the ticket is not valid"),
    (0x0A2, "TPM_RC_BAD_AUTH: the authorization value is wrong"),
    (0x0A3, "TPM_RC_EXPIRED: the policy expired"),
    (0x0A4, "TPM_RC_POLICY_CC: the policy is for another command"),
    (0x0A6, "TPM_RC_CURVE: the curve is not supported"),
    (0x0A7, "TPM_RC_ECC_POINT: the point is not on the curve"),
];

/// The format-zero codes of TPM 2.0 (bit 8 set) and its warnings (0x900).
const FORMAT_ZERO: &[(u32, &str)] = &[
    (0x100, "TPM_RC_INITIALIZE: the TPM was not started"),
    (0x101, "TPM_RC_FAILURE: the TPM is in its failure mode"),
    (0x103, "TPM_RC_SEQUENCE: the sequence of commands is not right"),
    (0x120, "TPM_RC_DISABLED: the command is disabled"),
    (0x124, "TPM_RC_AUTH_TYPE: the command needs an authorization of another type"),
    (0x125, "TPM_RC_AUTH_MISSING: the command needs an authorization"),
    (0x126, "TPM_RC_POLICY: the policy session is not right for the command"),
    (0x127, "TPM_RC_PCR: the PCRs are not right"),
    (0x128, "TPM_RC_PCR_CHANGED: the PCRs changed while the policy ran"),
    (0x12E, "TPM_RC_TOO_MANY_CONTEXTS: the TPM holds too many contexts"),
    (0x12F, "TPM_RC_AUTH_UNAVAILABLE: the key takes no authorization of this kind"),
    (0x130, "TPM_RC_REBOOT: the TPM must be started again"),
    (0x142, "TPM_RC_COMMAND_SIZE: the command's size is not right"),
    (0x143, "TPM_RC_COMMAND_CODE: the TPM does not know the command"),
    (0x902, "TPM_RC_OBJECT_MEMORY: the TPM has no room for another object"),
    (0x903, "TPM_RC_SESSION_MEMORY: the TPM has no room for another session"),
    (0x904, "TPM_RC_MEMORY: the TPM is out of memory"),
    (0x908, "TPM_RC_YIELDED: the TPM yielded; try again"),
    (0x909, "TPM_RC_CANCELED: the command was canceled"),
    (0x90A, "TPM_RC_TESTING: the TPM is testing itself; try again"),
    (0x920, "TPM_RC_NV_RATE: the TPM limits writes now; try again later"),
    (0x921, "TPM_RC_LOCKOUT: the TPM is locked out after failed authorizations"),
    (0x922, "TPM_RC_RETRY: the TPM asks to try again"),
];

/// The format-one code of `code` (bit 7 set): its number, and what it is
/// of: a parameter, a session or a handle, each counted from 1.
pub(super) fn format_one(code: u32) -> Option<(u32, Of)> {
    if code & 0x080 == 0 {
        return None;
    }
    let number = 0x080 | (code & 0x03F);
    let n = (code >> 8) & 0xF;
    let of = if code & 0x040 != 0 {
        Of::Parameter(n)
    } else if n & 0x8 != 0 {
        Of::Session(n & 0x7)
    } else if n != 0 {
        Of::Handle(n)
    } else {
        Of::Nothing
    };
    Some((number, of))
}

/// What a format-one code is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Of {
    Parameter(u32),
    Session(u32),
    Handle(u32),
    Nothing,
}

/// One line for `code`: its name and meaning, what it is of, and its
/// number.
pub(super) fn describe(code: u32) -> String {
    let layer = code >> 16;
    if layer != 0 {
        // Not the TPM's: a resource manager or a driver in front of it.
        return format!("the TPM's resource manager (layer {layer}) refused the command, code {code:#010x}");
    }
    if let Some((number, of)) = format_one(code) {
        let words = name(FORMAT_ONE, number).unwrap_or("an error of the TPM");
        let place = match of {
            Of::Parameter(n) => format!(", of parameter {n}"),
            Of::Session(n) => format!(", of session {n}"),
            Of::Handle(n) => format!(", of handle {n}"),
            Of::Nothing => String::new(),
        };
        return format!("{words}{place} (code {code:#06x})");
    }
    if code & 0x100 == 0 {
        return format!("an answer of a TPM 1.2, code {code:#06x}: podssh speaks TPM 2.0");
    }
    let words = name(FORMAT_ZERO, code & 0xFFF).unwrap_or("an error of the TPM");
    format!("{words} (code {code:#06x})")
}

fn name(table: &[(u32, &'static str)], number: u32) -> Option<&'static str> {
    table.iter().find(|(n, _)| *n == number).map(|(_, words)| *words)
}

/// The base code of `code`, without what it is of: for a comparison with a
/// constant of part 2.
pub(super) fn base(code: u32) -> u32 {
    match format_one(code) {
        Some((number, _)) => number,
        None => code & 0xFFF,
    }
}

pub(super) const VALUE: u32 = 0x084;
pub(super) const POLICY_FAIL: u32 = 0x09D;
pub(super) const INTEGRITY: u32 = 0x09F;
pub(super) const BAD_AUTH: u32 = 0x0A2;
pub(super) const AUTH_FAIL: u32 = 0x08E;
pub(super) const AUTH_UNAVAILABLE: u32 = 0x12F;
pub(super) const LOCKOUT: u32 = 0x921;
pub(super) const PCR_CHANGED: u32 = 0x128;
