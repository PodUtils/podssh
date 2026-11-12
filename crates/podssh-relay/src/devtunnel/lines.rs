//! The events of `pod-devtunnel` as podssh's lines: a warning (a relay
//! session that ended, a reconnect) goes to the user's line, a step that
//! went as planned (`devtunnel.connected`) to `-v`. The crate's events
//! hold no token, so a line passes them as they are.

use std::sync::Arc;

use pod_core::{Event, Events, Level, NoObserver, Report};

/// Where a line goes: one function for each level.
pub type Say = Arc<dyn Fn(&str) + Send + Sync>;

struct Lines {
    info: Say,
    verbose: Say,
}

impl Events for Lines {
    fn event(&self, event: Event) {
        match event.level {
            Level::Warn => (self.info)(&event.text),
            Level::Info => (self.verbose)(&event.text),
        }
    }
}

/// The report of the crate, its warnings to `info` and the rest to
/// `verbose`; its decisions are not counted.
pub fn report(info: Say, verbose: Say) -> Report {
    Report { events: Arc::new(Lines { info, verbose }), observer: Arc::new(NoObserver) }
}

/// A report that drops each event.
pub fn quiet() -> Report {
    Report::default()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn devtunnel_a_warning_is_the_user_s_line_and_a_step_is_verbose() {
        let kept: Arc<Mutex<Vec<String>>> = Arc::default();
        let (a, b) = (kept.clone(), kept.clone());
        let info: Say = Arc::new(move |l| a.lock().unwrap().push(format!("info {l}")));
        let verbose: Say = Arc::new(move |l| b.lock().unwrap().push(format!("verbose {l}")));
        let report = report(info, verbose);
        report.event(Event::info("devtunnel.connected", "up"));
        report.event(Event::warn("devtunnel.reconnect", "again"));
        assert_eq!(*kept.lock().unwrap(), ["verbose up", "info again"]);
    }
}
