//! The variables of the terminal, the pager, the editor and the shell, for
//! ENVIRONMENT: a part of [`super::VARIABLES`] of their own, as one file
//! would pass its 500 lines.

pub const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["TERM", "SSH_TTY"],
        "Sent to the server with a pty request; xterm-256color when it is not set. podssh serve gives a child \
         on a pty the client's TERM, and SSH_TTY the pty's name.",
    ),
    (
        &["COLUMNS", "LINES"],
        "The window size sent with a pty request when there is no terminal to measure (80 and 24 when \
      they are not set).",
    ),
    (&["COMPUTERNAME"], "On Windows, the host name in the default comment of podssh keygen."),
    (&["ProgramData"], "On Windows, the directory of the system known_hosts file."),
    (&["SystemRoot"], "On Windows, where an sshd of OpenSSH is looked for (System32\\OpenSSH): a roost that the loopback refuses, and doctor's line sshd."),
    (
        &["SystemDrive"],
        "On Windows, the drive whose root a detached run takes as its working directory (see podssh ssh -f).",
    ),
    (&["PAGER"], "The pager of podssh man on a terminal. Empty, or cat, writes the manual with no pager."),
    (
        &["SHELL", "BASH_ENV"],
        "The shell of LocalCommand with PermitLocalCommand=yes: SHELL -c COMMAND; empty or not set, /bin/sh \
      when it is there, else podssh ssh exits 78. podssh serve: the first shell it tries after --shell, \
      when it runs; else it is passed over, and said (see podssh serve). podssh serve never takes SHELL or \
      BASH_ENV from a client's env request: the shell would run, or read, the file it names.",
    ),
    (
        &["SSH_ORIGINAL_COMMAND"],
        "Set by podssh serve for a command that a key's command=\"...\" runs in place of the client's: the \
      client's command (internal-sftp for an sftp request; not set for a shell). Never taken from a client's \
      env request, and serve's own never reaches a child (see podssh serve).",
    ),
    (&["LESS"], "Options for less. podssh man sets FRX when it starts less and LESS is not set."),
    (
        &["VISUAL", "EDITOR"],
        "The editor of podssh edit: VISUAL, else EDITOR, else vi on PATH. A program and its words, split at \
      blanks with no shell, or one program whose path has a blank; an empty value is no value.",
    ),
    (
        &["PATH"],
        "Where podssh man looks for less, podssh edit for vi, and podssh doctor for directories that run programs.",
    ),
];
