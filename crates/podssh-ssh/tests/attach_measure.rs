//! The measure of T-161's step 1, run on demand: what a new client's screen
//! shows when it attaches to a kept shell that runs `vi`, `less`, `top` or
//! nothing but its prompt, joined fresh (no count) and with a reset. Each
//! row printed is one program and one way: the rows of text that the new
//! screen shares with the first client's last screen, whether the new
//! screen shows the program's ready text, whether its modes are the far
//! end's, and the bytes that came within the wait. The numbers go to
//! `docs/terminal.md` ("Screen on attach"); `attach_screen.rs` holds the
//! rule that the gate checks.
//!
//! `cargo test -p podssh-ssh --test attach_measure -- --ignored --nocapture`

#![cfg(unix)]

mod kept_harness;
mod share_harness;

use std::num::NonZeroU16;
use std::time::Duration;

use kept_harness::{detach, server, shell_with};
use share_harness::{have_pty, key};

const ROWS: u16 = 24;
const COLS: u16 = 80;
/// How long the new client reads before its screen is measured.
const SETTLE: Duration = Duration::from_secs(3);

/// The rows of text (trimmed, non-empty) and the modes of a model terminal
/// that read `bytes` from its start.
fn model(bytes: &[u8]) -> (Vec<String>, [bool; 4]) {
    let mut parser = vt100::Parser::new(NonZeroU16::new(ROWS).unwrap(), NonZeroU16::new(COLS).unwrap(), 0);
    parser.process(bytes);
    let s = parser.screen();
    let rows = s.rows(0, COLS).map(|r| r.trim_end().to_string()).filter(|r| !r.is_empty()).collect();
    (rows, [s.alternate_screen(), s.application_cursor(), s.application_keypad(), s.bracketed_paste()])
}

fn found(program: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// One program: its name, the line typed, the text that says it drew, and
/// the keys that end it.
struct Program {
    name: &'static str,
    command: String,
    ready: &'static str,
    quit: &'static [&'static [u8]],
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measure, run on demand: its numbers go to docs/terminal.md"]
async fn measure_the_screen_of_an_attach() {
    if !have_pty() {
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "podssh-attach-measure-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let text = dir.join("text");
    let lines: String = (1..=60).map(|n| format!("line {n} of the file\n")).collect();
    std::fs::write(&text, lines).unwrap();
    let t = text.display();
    let mut programs = vec![Program {
        name: "shell",
        command: "printf 'the shell said this\\n'\r".to_string(),
        ready: "the shell said this",
        quit: &[],
    }];
    const VI_QUIT: &[&[u8]] = &[b"\x1b", b":q!\r"];
    const Q: &[&[u8]] = &[b"q"];
    for (name, command, ready, quit) in [
        ("vi", format!("TERM=xterm vi {t}\r"), "line 2 of the file", VI_QUIT),
        ("less", format!("TERM=xterm less {t}\r"), "line 2 of the file", Q),
        ("top", "TERM=xterm top -d 1\r".to_string(), "Mem", Q),
    ] {
        if found(name) {
            programs.push(Program { name, command, ready, quit });
        } else {
            eprintln!("did not run: {name}: none on this host");
        }
    }
    println!("program | join | shared rows | ready text | modes | bytes");
    for program in &programs {
        for (join, asks) in [("fresh", &[][..]), ("reset", &[("reset@podssh", "yes")][..])] {
            let owner = key();
            let server = server(Duration::from_secs(600), &[&owner]);
            let first = shell_with(&server, &owner, &[]).await;
            first.send(program.command.as_bytes()).await;
            first.reads(program.ready).await;
            tokio::time::sleep(Duration::from_millis(800)).await;
            assert!(detach(&first, "work").await, "{}", program.name);
            first.until("the channel's close", |seen| seen.closed).await;
            let (rows, modes) = model(&first.seen.lock().unwrap().out);

            let mut all = asks.to_vec();
            all.push(("attach@podssh", "work"));
            let back = shell_with(&server, &owner, &all).await;
            tokio::time::sleep(SETTLE).await;
            let out = back.seen.lock().unwrap().out.clone();
            let (new_rows, new_modes) = model(&out);
            let shared = new_rows.iter().filter(|r| rows.contains(r)).count();
            let ready = new_rows.iter().any(|r| r.contains(program.ready));
            println!(
                "{} | {join} | {shared} of {} | {} | {} | {}",
                program.name,
                rows.len(),
                if ready { "yes" } else { "no" },
                if new_modes == modes { "same" } else { "differ" },
                out.len()
            );
            for keys in program.quit {
                back.send(keys).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            back.send(b"exit 0\r").await;
            back.until("the shell's end", |seen| seen.closed).await;
        }
    }
    // Step 3's cost: a model of the screen on the far end, for each kept
    // shell: its cells, 80 by 24 and 1,000 lines of scrollback.
    let cell = std::mem::size_of::<vt100::Cell>();
    let screen = cell * usize::from(ROWS) * usize::from(COLS);
    let scrollback = cell * 1000 * usize::from(COLS);
    println!("a cell of vt100: {cell} bytes; a screen: {screen} bytes; 1,000 lines of scrollback: {scrollback} bytes");
    let _ = std::fs::remove_dir_all(&dir);
}
