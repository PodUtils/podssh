//! The commands that `ssh_exec` may run, by `--allow-command PATTERN`
//! (T-731): a pattern is words, its first the program as typed, `*` one
//! word of any text. A command matches when its words, split on blanks, are
//! as many and each the pattern's or under its `*`. The remote user's shell
//! reads the command line, so a character that would make it run more, or
//! other words, than those seen here is refused: the separators and pipes,
//! the expansions, the redirections, the quotes, the escapes and the globs.
//! The patterns are the user's, never the agent's.

/// The characters that the remote shell reads as more than a word's text.
const SHELL: &[char] = &[
    ';', '|', '&', '$', '`', '<', '>', '(', ')', '\n', '\r', '\\', '\'', '"', '*', '?', '[', ']', '{', '}', '~', '#',
    '!', '=', '%',
];

/// The patterns of `--allow-command`, each one's words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Commands {
    patterns: Vec<Vec<String>>,
}

impl Commands {
    /// The patterns of the command line; an empty one, one whose program is
    /// `*`, or one with a character of the shell other than a word `*`, is
    /// refused.
    pub fn new(patterns: &[String]) -> Result<Commands, String> {
        let mut out = Vec::new();
        for pattern in patterns {
            let words: Vec<String> = pattern.split_whitespace().map(str::to_string).collect();
            let Some(program) = words.first() else {
                return Err(format!("--allow-command {pattern:?}: a pattern names a program"));
            };
            if program == "*" {
                return Err(format!("--allow-command {pattern:?}: the program is named as typed, never *"));
            }
            if let Some(word) = words.iter().find(|w| *w != "*" && w.contains(SHELL)) {
                return Err(format!(
                    "--allow-command {pattern:?}: {word:?} holds a character that the shell reads; a word is plain \
                     text, or * for one word"
                ));
            }
            out.push(words);
        }
        Ok(Commands { patterns: out })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The patterns as the tool's description gives them.
    pub fn shown(&self) -> String {
        let each: Vec<String> = self.patterns.iter().map(|words| format!("'{}'", words.join(" "))).collect();
        each.join(", ")
    }

    /// Whether `command` may run: always with no pattern.
    pub fn check(&self, command: &str) -> Result<(), String> {
        if self.patterns.is_empty() {
            return Ok(());
        }
        if let Some(c) = command.chars().find(|c| SHELL.contains(c) || (c.is_control() && *c != '\t')) {
            return Err(format!(
                "command: {c:?} is read by the remote shell, so the command could run more than a pattern of \
                 --allow-command says; the patterns: {}",
                self.shown()
            ));
        }
        let words: Vec<&str> = command.split_whitespace().collect();
        let fits = |pattern: &Vec<String>| {
            pattern.len() == words.len() && pattern.iter().zip(&words).all(|(p, w)| p == "*" || p == w)
        };
        if self.patterns.iter().any(fits) {
            Ok(())
        } else {
            Err(format!("command: no pattern of --allow-command matches it; the patterns: {}", self.shown()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(patterns: &[&str]) -> Commands {
        Commands::new(&patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn allow_command_matches_whole_words_and_star_is_one_word() {
        let commands = of(&["uptime", "systemctl status *", "df -h"]);
        for good in ["uptime", "  uptime ", "systemctl status nginx", "df -h"] {
            assert_eq!(commands.check(good), Ok(()), "{good}");
        }
        for bad in
            ["uptime -p", "systemctl status", "systemctl status a b", "systemctl stop nginx", "df", "/usr/bin/uptime"]
        {
            assert!(commands.check(bad).unwrap_err().contains("no pattern"), "{bad}");
        }
        assert_eq!(of(&[]).check("rm -rf /"), Ok(()), "no pattern: as before");
    }

    #[test]
    fn allow_command_refuses_what_the_remote_shell_would_read_as_more() {
        let commands = of(&["uptime", "cat *"]);
        for bad in [
            "uptime; id",
            "uptime && id",
            "uptime | sh",
            "cat $(id)",
            "cat `id`",
            "cat /etc/*",
            "cat >x",
            "cat a\nid",
            "cat 'a b'",
            "cat ~root/x",
            "cat a\\ b",
        ] {
            assert!(commands.check(bad).unwrap_err().contains("read by the remote shell"), "{bad:?}");
        }
    }

    #[test]
    fn allow_command_patterns_name_a_program_in_plain_words() {
        let new = |p: &str| Commands::new(&[p.to_string()]);
        assert!(new("").unwrap_err().contains("names a program"));
        assert!(new("* status").unwrap_err().contains("never *"));
        assert!(new("ls; id").unwrap_err().contains("character that the shell reads"));
        assert_eq!(new("journalctl -u * -n 50").unwrap().shown(), "'journalctl -u * -n 50'");
    }
}
