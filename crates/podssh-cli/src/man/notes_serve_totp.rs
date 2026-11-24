//! The note of `podssh serve --totp` (T-115): the second factor after a
//! key, its secret and its state, and `--totp-new`.

pub const TOTP: &str = "--totp FILE asks each key that passes for a one-time code too, as sshd with PAM asks for \
     one. The key gets a partial success, then keyboard-interactive shows one prompt, One-time code:, with no echo. \
     The code is RFC 6238's: HMAC-SHA-1, a step of 30 s, six digits, as authenticator apps and oathtool --totp -b \
     compute it. A code of the step before or after now is taken too, for a clock that is off. A code is taken once: \
     a second use, or an older code after it, is refused. Each failure of a key makes it wait longer before the next \
     try: 1 s, then twice as long, at most 60 s. After three wrong codes on one connection, the client must sign \
     with its key again. FILE holds the secret in base32 on one line, at least 80 bits; spaces and case do not \
     count. A FILE that others may read, another user's, or no secret refuses the start (78). serve keeps the last \
     step taken and each key's failures in FILE.used, mode 0600, under the lock of FILE. So two serve processes \
     never take one code twice. A FILE.used that does not read refuses each code, and says to remove it. podssh \
     serve --totp-new FILE makes a secret of 160 bits, mode 0600, never over a file that is there. It prints the \
     path alone, and exits 0, or 73 when FILE cannot be made. Load the file's one line into an authenticator app. A \
     name of --share logs in with no code, as the name alone is its right. serve's stderr and the audit log say a \
     refused code and why, never the code or the secret.";
