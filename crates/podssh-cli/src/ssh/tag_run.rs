//! `podssh ssh [user@]tag:NAME` (T-750, `crate::net::tag`): each member of
//! the tag in its order, as `node://[user@]MEMBER`, until a race reaches one.
//! The run ends at the first member that a race reached (`crate::net::reached`
//! records it), whatever came after, a command or a login that failed: with
//! no such record nothing ran there, and the next member is tried; so
//! nothing runs twice. A line names each member tried and the one used; when none was
//! reached, a line names each cause, and the exit code is the last one's.

use std::io::Write;

use crate::exitmap::sysexits::EX_USAGE;
use crate::net::{reached, tag};
use crate::pager::Tty;

use crate::ssh::args::SshArgs;

/// `run` for the destination of `args`, each member in turn when it names a tag.
pub(crate) fn run_or(
    args: &SshArgs,
    tty: Tty,
    err: &mut dyn Write,
    run: fn(&SshArgs, Tty, &mut dyn Write) -> i32,
) -> i32 {
    let Some((user, name)) = args.destination.as_deref().and_then(tag::parse) else {
        return run(args, tty, err);
    };
    let members = match tag::members(&name) {
        Ok(members) => members,
        Err(why) => {
            let _ = writeln!(err, "podssh ssh: {why}");
            return EX_USAGE;
        }
    };
    let order = tag::order(members, &tag::holds(), crate::pairs::now_ms() as u64);
    let (count, mut missed, mut code) = (order.len(), Vec::new(), EX_USAGE);
    for (at, member) in order.iter().enumerate() {
        let target = match &user {
            Some(user) => format!("node://{user}@{member}"),
            None => format!("node://{member}"),
        };
        let _ = writeln!(err, "podssh ssh: tag:{name}: {member}, {} of {count}", at + 1);
        let one = SshArgs { destination: Some(target), ..args.clone() };
        let _ = reached::take_last();
        code = run(&one, tty, err);
        // A race that reached the member is the only way to a command: with
        // none recorded (no road at all, or none that answered), nothing ran.
        if reached::take_last().is_some_and(|(label, won)| won && label == *member) {
            let _ = writeln!(err, "podssh ssh: tag:{name}: used {member}");
            return code;
        }
        tag::hold(member, crate::pairs::now_ms() as u64);
        missed.push(member.clone());
    }
    let _ = writeln!(
        err,
        "podssh ssh: tag:{name}: no member was reached: {}; each is held last for {} s",
        missed.join(", "),
        tag::HOLD.as_secs()
    );
    code
}
