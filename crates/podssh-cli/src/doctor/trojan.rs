//! Trojan's controls by name (T-761, VEC-6): a TCP stream to a target is
//! carried, and UDP associate is refused with why. The line reads the road's
//! `capability()`, never a failure's words, so a control that the road stops
//! carrying appears here without a second list. No connection is made: the
//! answer is what this client's Trojan speaks.

use podssh_ws::trojan::{self, Capability};

use super::Report;

/// The line of each command that Trojan names.
pub(super) fn check(report: &mut Report<'_>) {
    for (command, carried) in trojan::capability() {
        match (command, carried) {
            (Capability::Tcp, true) => report.ok("trojan", command.words().to_string()),
            (Capability::UdpAssociate, false) => report.ok("trojan", command.words().to_string()),
            (command, carried) => report.fail(
                "trojan",
                format!(
                    "{} is {}, where the road says {}: the doctor and the road disagree",
                    command_label(command),
                    if carried { "carried" } else { "refused" },
                    command.words()
                ),
            ),
        }
    }
}

/// The command's name alone, for a disagreement.
fn command_label(capability: Capability) -> &'static str {
    match capability {
        Capability::Tcp => "TCP (command 0x01)",
        Capability::UdpAssociate => "UDP associate (command 0x03)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines() -> (i32, String) {
        let mut out = Vec::new();
        let code = {
            let mut report = Report::new(&mut out);
            report.section("trojan");
            check(&mut report);
            report.finish()
        };
        (code, String::from_utf8(out).unwrap())
    }

    /// VEC-6: UDP associate is refused by name with its reason, never left
    /// out, and the TCP stream is carried.
    #[test]
    fn udp_associate_is_refused_by_name_with_the_reason() {
        let (code, text) = lines();
        assert_eq!(code, 0, "{text}");
        assert!(text.contains(Capability::Tcp.words()), "{text}");
        // The road's live answer, read from the same function that the check
        // reads, not a verdict the test made up.
        let (_, carried) = trojan::capability()
            .iter()
            .copied()
            .find(|(command, _)| *command == Capability::UdpAssociate)
            .expect("the road names UDP associate");
        assert!(!carried, "the road refuses UDP associate");
        let reason = Capability::UdpAssociate.words();
        let line = text
            .lines()
            .find(|l| l.contains("trojan") && l.contains("0x03"))
            .unwrap_or_else(|| panic!("a line for UDP associate: {text}"));
        assert!(line.contains("ok"), "the refusal is the road's answer, not a failure: {line}");
        assert!(line.contains(reason), "the refusal names its reason: {line}");
        assert_eq!(text.lines().filter(|l| l.contains("ok") && l.contains("trojan")).count(), 2, "{text}");
    }
}
