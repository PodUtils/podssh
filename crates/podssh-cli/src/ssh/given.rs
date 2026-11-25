//! Where the value of a keyword was given: `-o` on the command line, or a
//! line of an `ssh_config` file. A note and a refusal name that place
//! (T-502, T-505), so that a user finds the line that asked for it.

/// The place of one value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Place {
    /// `-o` on the command line, or a flag of podssh's that gives a keyword.
    #[default]
    CommandLine,
    /// `FILE:LINE`, as the refusals of a file name it; `system` for the
    /// system's file and each file that it includes, which a distribution
    /// writes for each program, not the user.
    Line { at: String, system: bool },
}

impl Place {
    /// The line `line` of `file`.
    pub fn line(file: &str, line: usize, system: bool) -> Place {
        Place::Line { at: format!("{file}:{line}"), system }
    }

    /// How a note names it: `-o`, or `FILE:LINE`.
    pub fn shown(&self) -> &str {
        match self {
            Place::CommandLine => "-o",
            Place::Line { at, .. } => at,
        }
    }

    /// The user's own: the command line, the file of `-F` or of
    /// `PODSSH_SSH_CONFIG`, `~/.ssh/config`, and the files that they include.
    pub fn users(&self) -> bool {
        !matches!(self, Place::Line { system: true, .. })
    }
}

/// A value as it was given: its keyword as written, the value, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Given {
    pub name: String,
    pub value: String,
    pub place: Place,
}

impl Given {
    pub fn new(name: &str, value: &str, place: &Place) -> Given {
        Given { name: name.to_string(), value: value.to_string(), place: place.clone() }
    }
}

/// Keep `given` in `list` when no value of its keyword is there yet: the
/// first one holds, as in OpenSSH, and its place is the one a note names.
pub fn keep_first(list: &mut Vec<Given>, given: Given) {
    if !list.iter().any(|g| g.name.eq_ignore_ascii_case(&given.name)) {
        list.push(given);
    }
}

/// The refusal of a value that was read after the files, as of its `%`
/// tokens: `why` names it as `-o NAME=VALUE: ...`. A value that a line of a
/// file gave is named by that `FILE:LINE` and is 78, as each other refusal
/// of a file's line; one of `-o` stays a refusal of the command line, 64.
pub fn placed(origins: &[Given], why: String) -> crate::relay_settings::Refusal {
    use crate::relay_settings::Refusal;
    let placed = why.strip_prefix("-o ").and_then(|rest| {
        let (name, after) = rest.split_once('=')?;
        let item = after.split(": ").next().unwrap_or_default();
        let line = origins.iter().find(|g| g.name.eq_ignore_ascii_case(name) && g.value.contains(item))?;
        match &line.place {
            Place::Line { at, .. } => Some(format!("{at}: {rest}")),
            Place::CommandLine => None,
        }
    });
    match placed {
        Some(message) => Refusal::config(message),
        None => Refusal::usage(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal names the line that gave the value, with 78; one of -o, or
    /// of a value that no line gave, stays as it was, with 64.
    #[test]
    fn a_refusal_after_the_files_names_the_line_that_gave_the_value() {
        const USAGE: i32 = crate::exit_codes::EXIT_USAGE;
        let file = Place::line("/home/u/.ssh/config", 7, false);
        let origins = [
            Given::new("UserKnownHostsFile", "/k/%Q /k/b", &file),
            Given::new("IdentityFile", "/id/%Z", &Place::CommandLine),
        ];
        for (why, code, said) in [
            (
                "-o UserKnownHostsFile=/k/%Q: %Q is not a token",
                crate::exitmap::sysexits::EX_CONFIG,
                "/home/u/.ssh/config:7: UserKnownHostsFile=/k/%Q: %Q is not a token",
            ),
            ("-o IdentityFile=/id/%Z: %Z is not a token", USAGE, "-o IdentityFile=/id/%Z: %Z is not a token"),
            ("-o ControlPath=/c/%Q: %Q is not a token", USAGE, "-o ControlPath=/c/%Q: %Q is not a token"),
            ("no keyword at all", USAGE, "no keyword at all"),
        ] {
            let refusal = placed(&origins, why.to_string());
            assert_eq!((refusal.code, refusal.message.as_str()), (code, said), "{why}");
        }
    }

    #[test]
    fn a_place_is_named_as_the_refusals_name_it_and_the_system_file_is_not_the_users() {
        assert_eq!(Place::CommandLine.shown(), "-o");
        let line = Place::line("/home/u/.ssh/config", 4, false);
        assert_eq!(line.shown(), "/home/u/.ssh/config:4");
        assert!(line.users() && Place::CommandLine.users());
        assert!(!Place::line("/etc/ssh/ssh_config", 22, true).users());
        let mut list = Vec::new();
        keep_first(&mut list, Given::new("HashKnownHosts", "yes", &line));
        keep_first(&mut list, Given::new("hashknownhosts", "no", &Place::CommandLine));
        assert_eq!(list, [Given::new("HashKnownHosts", "yes", &line)], "the first one holds");
    }
}
