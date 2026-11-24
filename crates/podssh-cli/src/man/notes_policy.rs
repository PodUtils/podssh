//! The notes of `--policy FILE`, an algorithm policy: its grammar and its
//! verdict under `podssh ssh`, its probe under `podssh health`, its gate
//! under `podssh serve`, its line under `podssh doctor --hop`, and its words
//! in EXIT STATUS. Apart from the others so that each file stays short;
//! `notes_roads`, `notes_health`, `notes_serve` and `notes` name these
//! paragraphs.

use podssh_ssh::policy::{EXIT_MISMATCH, EXIT_NO_READING, EXIT_PASS};

use super::data::Code;

/// `podssh ssh --policy FILE`: where the verdict falls.
pub const SSH_JUDGE: &str = "POLICY: with --policy FILE, podssh ssh judges the destination's algorithms by an \
     algorithm policy. The verdict falls at the server's host key, before known_hosts is read and before any login. \
     A mismatch ends the run with exit 78, and a KEXINIT that does not read ends it with exit 69. Either way the \
     verdict goes to stdout as one JSON object. A pass goes on to the login, and -v says the verdict. So does a size \
     that one exchange cannot measure: -v names it unmeasured, and only podssh health exits 69 for it. A host of -J \
     is not judged. --policy goes with no --persist, --upgrade, -M, -S or -O (64); ControlPath of a file has no \
     effect then.";

/// The grammar of the file.
pub const GRAMMAR: &str = "The file is in the grammar of ssh-audit, whose policy files load unchanged. Each line is \
     KEY = VALUE, and a line that starts with # is a comment. name and version are required; banner and header are \
     compared whole. compressions, host keys, key exchanges, ciphers and macs are lists by commas, expected in that \
     order; optional host keys may come beside the host keys. allow_algorithm_subset_and_reordering = true takes the \
     key exchanges, ciphers and MACs in any order, each one named by the policy. \
     allow_hostkey_subset_and_reordering = true does the same for the host keys. host_key_sizes is JSON, as \
     {\"rsa-sha2-512\": {\"hostkey_size\": 4096}}, with ca_key_type and ca_key_size for a certificate. \
     dh_modulus_sizes is JSON too, and the older lines hostkey_size_ALG, cakey_size_ALG and dh_modulus_size_KEX \
     are read. A size must be equal, or at least as large with allow_larger_keys = true. client policy = true \
     judges a client, so it finds a mismatch on a server. An unknown key, a key given twice, or a value that does \
     not read is refused with its line (78).";

/// What the verdict reads, and what it says.
pub const VERDICT: &str = "A size is read on the key that came, of the type that the exchange agreed. A key of \
     another type is a mismatch, and its size counts for nothing. One exchange measures one host key, so the size of \
     another type that the server offers is said as unmeasured, never passed. ext-info-s and the name of the strict \
     key exchange are judged only by a policy that names one of them. The verdict is one JSON object: schema, \
     policy, version, verdict (pass, mismatch, unmeasured or no reading), exit, mismatches, unmeasured, and why with \
     no reading. Each mismatch has field, expected, optional and actual.";

/// `podssh health --policy FILE`: a probe with no login.
pub const HEALTH_PROBE: &str = "POLICY: with --policy FILE, podssh health gives no facts. It reaches the host as \
     podssh ssh does, and runs the handshake to the server's host key. There the policy judges the server's \
     algorithms, and the connection ends. Nothing is sent to log in to the destination, so no key or password is \
     needed, and known_hosts is not read. The file and the verdict are those of podssh ssh --policy. The verdict is \
     one JSON object on stdout, with or without --json. The exit is 0 for a pass and 78 for a mismatch. It is 69 \
     for no reading: no connection, a KEXINIT that does not read, or a size that one exchange cannot measure. \
     --policy goes with no --preflight (64).";

/// `podssh serve --policy FILE`: a client policy, before authentication.
pub const SERVE_JUDGE: &str = "POLICY: with --policy FILE, podssh serve judges each client's algorithms, before \
     authentication. The file must say client policy = true; another is refused at the start (78). The policy reads \
     the client's first KEXINIT: its key exchanges, host keys, and the ciphers, MACs and compressions it sends with. \
     A mismatch, or a KEXINIT that does not read, ends the connection. The client gets a disconnect that names the \
     policy, and no key logs in. One line on stderr names the client's address and each mismatch, as doctor does: \
     FIELD: expected A,B, got C. A client offers \
     no host key, so a size rule never refuses one.";

/// `podssh doctor --hop HOST --policy FILE`: one line of the report.
pub const DOCTOR_LINE: &str = "POLICY: with --hop HOST, --policy FILE judges the hop's algorithms by an algorithm \
     policy. One more connection runs the handshake to the hop's host key, and ends there. The file and the verdict \
     are those of podssh ssh --policy. The line hop policy is ok with the policy's name on a pass. It is FAIL on a \
     mismatch, naming each one as FIELD: expected A,B, got C. A FAIL makes the exit 1, as each FAIL of doctor does. \
     It is ???? with no reading, or with a size that one exchange cannot measure. --policy goes only with --hop (64). \
     A file that cannot be used is refused before any probe (78).";

/// `rows`, the EXIT STATUS table, with the words of `--policy` at its
/// codes.
pub fn exit_words(mut rows: Vec<(Code, String)>) -> Vec<(Code, String)> {
    for (code, what) in &mut rows {
        let words = match code {
            Code::Value(EXIT_PASS) => " podssh health --policy: the policy passed.",
            Code::Value(EXIT_NO_READING) => {
                " podssh ssh and health with --policy: a KEXINIT that does not read gives no verdict. podssh health \
                 --policy also gives none with no connection, or with a size that one exchange cannot measure."
            }
            Code::Value(EXIT_MISMATCH) => {
                " podssh ssh and health: the file of --policy cannot be read or used, or the server's algorithms do \
                 not meet it. podssh serve: the file of --policy cannot be used, or judges no client. podssh doctor: \
                 the file of --policy cannot be used."
            }
            _ => continue,
        };
        what.push_str(words);
    }
    rows
}
