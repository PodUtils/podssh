//! The screen that a new client finds when it attaches to a kept shell
//! (T-161), with russh's client over pipes in memory and the oracle's model
//! of a terminal (`vt100`, T-200) at each end. The client that ran a
//! full-screen program and detached saw the true screen. A client that
//! attaches from a new process starts with an empty terminal, and once the
//! attach settles its model must show the same rows, cursor and modes.
//!
//! A replay with no redraw leaves the new screen empty, as nothing came
//! since the detach; a replay cut after the program set its modes, with no
//! modes sent again, leaves the alternate screen and the keys off. Each
//! case needs a pty, and a host with none says so; `vi` runs where the host
//! has it, and a line says where it does not.

#![cfg(unix)]

mod kept_harness;
mod share_harness;

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kept_harness::{detach, server, shell_with};
use share_harness::{have_pty, key};

/// The size of each client's pty, as `shell_with` asks for it.
const ROWS: u16 = 24;
const COLS: u16 = 80;

/// A full-screen program in a few lines: it sets its modes once, as vi
/// does, then draws its screen at its start and at each window change.
/// With FLOOD, it first writes more than serve's ring holds, so that a
/// replay from the ring starts after the modes.
const STAND_IN: &str = r#"draw() {
  set -- $(stty size)
  printf '\033[H\033[2J'
  i=1
  while [ "$i" -lt "$1" ]; do printf 'row %d of %d\r\n' "$i" "$1"; i=$((i + 1)); done
  printf 'DRAWN %sx%s' "$2" "$1"
}
printf '\033[?1049h\033[?1h\033=\033[?2004h'
if [ -n "$FLOOD" ]; then yes 'a line of the flood that the ring of serve drops' | head -n "$FLOOD"; fi
trap draw WINCH
draw
while :; do sleep 1; done
"#;

/// What the oracle compares: the rows, the cursor, and the modes that the
/// keys and a paste depend on.
#[derive(Debug, PartialEq)]
struct Shown {
    rows: Vec<String>,
    cursor: (u16, u16),
    alternate: bool,
    cursor_keys: bool,
    keypad: bool,
    paste: bool,
}

/// `shown` cut to what each vi shows of the file: the rows that hold text
/// of it (trimmed of the padding that a redraw may write), and the modes.
fn text_and_modes(mut shown: Shown) -> Shown {
    shown.rows =
        shown.rows.iter().map(|row| row.trim_end().to_string()).filter(|row| row.contains("of the file")).collect();
    shown
}

/// The screen of a model terminal of [`ROWS`] by [`COLS`] that read
/// `bytes` from its start.
fn shown(bytes: &[u8]) -> Shown {
    let mut parser = vt100::Parser::new(NonZeroU16::new(ROWS).unwrap(), NonZeroU16::new(COLS).unwrap(), 0);
    parser.process(bytes);
    let s = parser.screen();
    Shown {
        rows: s.rows(0, COLS).collect(),
        cursor: s.cursor_position(),
        alternate: s.alternate_screen(),
        cursor_keys: s.application_cursor(),
        keypad: s.application_keypad(),
        paste: s.bracketed_paste(),
    }
}

/// A directory of this test's own, gone at its drop: a name that exists
/// already is passed over, as a pid is not unique across namespaces.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let base = std::env::temp_dir();
        for n in 0..1000u32 {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
            let dir = base.join(format!("podssh-attach-screen-{}-{nanos}-{n}", std::process::id()));
            if std::fs::create_dir(&dir).is_ok() {
                return Scratch(dir);
            }
        }
        panic!("no scratch directory in {}", base.display());
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Whether the host's shell finds `program`.
fn found(program: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// One case: the command typed in the first client's shell, the text that
/// says its screen is drawn, the asks of the attach, and whether it is the
/// stand-in, whose modes are known (a check of the case itself) and which
/// quits on Ctrl-C.
struct Case {
    name: &'static str,
    command: String,
    ready: &'static str,
    asks: &'static [(&'static str, &'static str)],
    stand_in: bool,
}

fn cases(stand_in: &Path, text: &Path) -> Vec<Case> {
    let sh = |env: &str| format!("{env}sh {}\r", stand_in.display());
    let mut cases = vec![
        Case {
            name: "a full-screen program, joined with no count",
            command: sh(""),
            ready: "DRAWN 80x24",
            asks: &[],
            stand_in: true,
        },
        Case {
            name: "a full-screen program whose modes the ring dropped, joined with a reset",
            command: sh("FLOOD=8000 "),
            ready: "DRAWN 80x24",
            asks: &[("reset@podssh", "yes")],
            stand_in: true,
        },
    ];
    if found("vi") {
        cases.push(Case {
            name: "vi, joined with no count",
            command: format!("TERM=xterm vi {}\r", text.display()),
            ready: "the second line of the file",
            asks: &[],
            stand_in: false,
        });
    } else {
        eprintln!("did not run: vi: no vi on this host");
    }
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_client_finds_the_screen_and_the_modes_of_a_kept_full_screen_program() {
    if !have_pty() {
        return;
    }
    let scratch = Scratch::new();
    let stand_in = scratch.file("stand-in.sh", STAND_IN);
    let text = scratch.file("text", "the first line of the file\nthe second line of the file\n");
    for case in cases(&stand_in, &text) {
        let owner = key();
        let server = server(Duration::from_secs(600), &[&owner]);
        let first = shell_with(&server, &owner, &[]).await;
        first.send(case.command.as_bytes()).await;
        first.reads(case.ready).await;
        // The program's last bytes, after the text that says it drew.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(detach(&first, "work").await, "{}", case.name);
        first.until("the channel's close", |seen| seen.closed).await;
        let want = shown(&first.seen.lock().unwrap().out);
        assert!(want.rows.iter().any(|row| row.contains(case.ready)), "{}: {want:?}", case.name);
        if case.stand_in {
            assert!(want.alternate && want.cursor_keys && want.keypad && want.paste, "{}: {want:?}", case.name);
        }

        let mut asks = case.asks.to_vec();
        asks.push(("attach@podssh", "work"));
        let back = shell_with(&server, &owner, &asks).await;
        // The stand-in draws the same screen at each size change, so the new
        // client's screen is the far end's, row for row. A vi redraws as it
        // likes (BusyBox's pads its lines and draws no `~`, and each drops
        // its last line's message), and the first client detached before
        // the redraw: the new client must show the file's text and the far
        // end's modes, whatever vi's own redraw.
        let want = if case.stand_in { want } else { text_and_modes(want) };
        let seen = |bytes: &[u8]| if case.stand_in { shown(bytes) } else { text_and_modes(shown(bytes)) };
        let waited = tokio::time::timeout(share_harness::LIMIT, async {
            while seen(&back.seen.lock().unwrap().out) != want {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let got = seen(&back.seen.lock().unwrap().out);
        assert!(waited.is_ok(), "{}: the new client's screen\n{got:#?}\nis not the far end's\n{want:#?}", case.name);

        // Out of the program, then out of the shell.
        // ESC apart from `:q!`: BusyBox's vi reads an ESC that a key follows
        // at once as the start of an escape sequence.
        if case.stand_in {
            back.send(b"\x03").await;
        } else {
            back.send(b"\x1b").await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            back.send(b":q!\r").await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        back.send(b"exit 0\r").await;
        back.until("the shell's end", |seen| seen.closed).await;
    }
}
