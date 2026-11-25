//! The notes of a verb that its flags cannot say: notes of its section of
//! the manual, which `--help` shows too. Apart from `help.rs` so that each
//! file stays short. A line break in a note keeps a command line whole.

use crate::flags::Verb;

/// The proxy of an SSH server, as `pipe --help` and the manual's examples
/// show it: one copy, which the examples' test parses.
pub const PROXY_OF_SSH: &str = "podssh pipe http-listen:3128 ssh:user@bastion.example.org";

/// The notes of a verb, one paragraph each.
pub fn verb_notes(verb: &Verb) -> Vec<String> {
    let mut s: Vec<String> = Vec::new();
    if verb.name == "pipe" {
        // The form of ssh: on the other side of a proxy is the one that a
        // user finds by trial (GitHub #93); a client on the port shows it.
        s.push(format!(
            "An HTTP CONNECT proxy whose connections go on from an SSH server, and a client:\n{PROXY_OF_SSH}\n\
             curl --proxy http://127.0.0.1:3128 https://example.org/"
        ));
        s.push(
            "ssh:HOPS with no target takes each CONNECT's %h:%p. A program that reads HTTPS_PROXY takes \
             HTTPS_PROXY=http://127.0.0.1:3128."
                .into(),
        );
    }
    if verb.name == "ssh" {
        s.push(
            "-L and -D listen here, and each connection that they take goes on from the server. -W HOST:PORT \
             carries one connection, with no listener."
                .into(),
        );
        s.push(
            "-R [BIND:]PORT:HOST:HOSTPORT: the server listens, and each connection reaches HOST:HOSTPORT from \
             here, through HTTPS_PROXY when it is set. A socket path can take the place of either side, or \
             [BIND:]PORT alone for SOCKS."
                .into(),
        );
        s.push(
            "-P on ssh is OpenSSH's Tag, which Match tagged reads, not a port. On scp and sftp, -P is the port. \
             The meaning is per-verb."
                .into(),
        );
    }
    if verb.name == "keygen" {
        s.push("-V here is the validity of a certificate, with -s. podssh -V prints the version.".into());
        s.push("-n, -s, -I, -O and -U mean one thing with -Y and another with -s, as in ssh-keygen.".into());
    }
    if matches!(verb.name, "cp" | "mv" | "scp" | "sftp" | "edit") {
        s.push("-P here is the port, as on scp and sftp. On ssh it is a Tag.".into());
    }
    if matches!(verb.name, "cp" | "mv" | "scp") {
        // Where a broken copy keeps its state, which a user found only by
        // trial (the report of 2026-11-02).
        s.push(
            "A copy that broke goes on when the same command runs again, while the source is as it was. A \
             side file in the cache, podssh-cp-*.resume, keeps the offset, never a byte of the file (podssh \
             man files)."
                .into(),
        );
    }
    if verb.name == "run" {
        // What never goes, and that an exclude removes nothing, which a user
        // could not tell from a defect of the copy (GitHub #103).
        s.push(
            "target/, node_modules/ and .git/ never go, at any depth, nor what the project's .podsshignore \
             names (a pattern a line). --no-ignore sends them. The summary counts what they left out, and -v \
             names each."
                .into(),
        );
        s.push("An exclude removes nothing on the host. What an earlier run sent stays.".into());
        s.push("podssh cp -r has no default excludes, and reads no .podsshignore.".into());
    }
    if verb.name == "job" {
        // The ID's form and fetch's 75, which the rows cannot say.
        s.push("ID is the 8 hex digits that start or submit printed, as list shows it.".into());
        s.push(
            "fetch of a job that is queued or running exits 75, as its output is not whole. Run podssh job \
             wait HOST ID first."
                .into(),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::VERBS;
    use crate::help::verb_help;

    fn verb(name: &str) -> &'static Verb {
        VERBS.iter().find(|v| v.name == name).unwrap()
    }

    fn squeeze(t: &str) -> String {
        t.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The part of a help before its list of options.
    fn before_options(help: &str) -> &str {
        &help[..help.find("\n  Options:\n").expect("an Options list")]
    }

    #[test]
    fn ssh_help_says_p_is_a_tag_here_and_a_port_on_scp() {
        let ssh = squeeze(&verb_help(verb("ssh")));
        let cp = verb_notes(verb("cp")).join(" ");
        assert!(ssh.contains("-P on ssh is OpenSSH's Tag"), "{ssh}");
        assert!(cp.contains("-P here is the port"), "{cp}");
    }

    /// `pipe --help` shows the proxy of an SSH server and its client, each
    /// on a line of its own, as a note: outside the list of options, so
    /// that no line of them is read as a flag.
    #[test]
    fn pipe_help_shows_the_proxy_of_an_ssh_server_with_its_client() {
        let pipe = verb_help(verb("pipe"));
        let notes = before_options(&pipe);
        assert!(notes.contains(&format!("\n  {PROXY_OF_SSH}\n")), "{pipe}");
        assert!(notes.contains("\n  curl --proxy http://127.0.0.1:3128 https://example.org/\n"), "{pipe}");
    }

    /// `pipe --help` names A and B in its usage, and each kind of address of
    /// the one table that the refusal of an unknown kind lists (T-916).
    #[test]
    fn pipe_help_names_a_and_b_and_each_kind_that_the_refusal_names() {
        let help = squeeze(&verb_help(verb("pipe")));
        assert!(help.contains("podssh pipe [OPTIONS] A B"), "{help}");
        let refusal = crate::pipe::address::parse("sctp:example.org:80").unwrap_err().message;
        for kind in crate::pipe::address::KINDS {
            assert!(help.contains(kind), "the help names {kind}: {help}");
            assert!(refusal.contains(kind), "the refusal names {kind}: {refusal}");
        }
    }

    /// `cp --help` says that a broken copy goes on from its side file, and
    /// where that file is.
    #[test]
    fn cp_help_says_where_a_broken_copy_goes_on() {
        for name in ["cp", "mv", "scp"] {
            let notes = squeeze(before_options(&verb_help(verb(name))));
            assert!(notes.contains("goes on when the same command runs again"), "{name}: {notes}");
            assert!(notes.contains("podssh-cp-*.resume"), "{name}: {notes}");
        }
        assert!(!verb_notes(verb("sftp")).join(" ").contains("podssh-cp-*.resume"));
    }

    /// `run --help` names what never goes and the file that adds to it, the
    /// flag that sends them, its dry run, and that an exclude removes
    /// nothing.
    #[test]
    fn run_help_names_the_default_excludes_and_the_ignore_file() {
        let help = squeeze(&verb_help(verb("run")));
        for word in [".podsshignore", "target/", "--no-ignore", "--dry-run", "removes nothing on the host"] {
            assert!(help.contains(word), "{word}: {help}");
        }
        let notes = verb_notes(verb("run")).join(" ");
        assert!(notes.contains("podssh cp -r has no default excludes"), "{notes}");
    }

    /// `job --help` says what an ID is, in its about and in its notes, and
    /// that fetch of a job that runs exits 75.
    #[test]
    fn job_help_names_the_id_and_the_75_of_fetch() {
        let help = squeeze(&verb_help(verb("job")));
        assert!(help.contains("8 hex digits that start or submit printed"), "{help}");
        let notes = verb_notes(verb("job")).join(" ");
        assert!(notes.contains("ID is the 8 hex digits that start or submit printed"), "{notes}");
        assert!(notes.contains("fetch of a job that is queued or running exits 75"), "{notes}");
    }
}
