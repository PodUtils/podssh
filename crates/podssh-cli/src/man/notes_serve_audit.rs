//! The note of `podssh serve --audit-log` (T-116): what a line holds and
//! never holds, the chain and what it cannot find, and `--audit-verify`.

pub const AUDIT: &str = "--audit-log FILE appends one JSON line for each event. They are serve's start and stop, a \
     connection, a login accepted or refused, a session's start and end, and a forward opened, refused or closed. \
     FILE is made with mode 0600; one that others may read, or another user's, refuses the start (78). Each line has \
     the keys schema, time (UTC), level, event and fields. The fields name the run, the connection, the channel and \
     the key's fingerprint. A session's end has its exit status or signal, the bytes each way and its duration. A \
     line never holds a key, a token, a value of the environment or what a session sent. With --share it holds no \
     login name, as a name of --share is the right to a shell. A command line is written only with --audit-commands, \
     as it can hold a password. Each run's first line, serve.start, has a map of what it records. Each line's \
     fields.prev is the SHA-256 of the line before it, so two serve processes append one chain. podssh serve \
     --audit-verify FILE recomputes it, and prints the last line's SHA-256. It exits 0 when the chain holds, 65 when \
     a line was changed, put in or removed, and 66 when FILE cannot be read. A command line in a run that declined \
     to record one also fails it. The chain finds an edit, and does not stop one. A cut of the tail reads as a run \
     with no serve.stop: keep the last hash off this host to find it. A write that fails, such as on a full disk, is \
     said once on stderr, and no session stops.";
