//! A file each way through a terminal that draws its own screen between
//! the far end and the session's pty, as tmux does (T-831, step 1 measured
//! it: tmux dropped ZMODEM's ZDLE and redrew the rest). The near end is
//! podssh's session ([`Zmodem`], as the pump drives it); the far end is the
//! far role of `pod_term::transfer`, which `podssh tx` runs. Between them,
//! [`Pane`] reads the far end's bytes as a screen: its control bytes never
//! pass, each row is drawn after a cursor move and erased after, a line
//! wider than the pane wraps onto the next row, a repaint draws each row
//! again, and a status line is drawn into the middle of the stream. The
//! clock is the test's own; a wait passes at once.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use pod_term::transfer::{Ended, Event, FileInfo, Transfer};
use podssh_ssh::zmodem::Zmodem;

use super::{names, scratch};

/// What the terminal between does to the far end's bytes, and what the
/// path loses of the near end's.
#[derive(Debug, Clone, Default)]
struct Damage {
    /// The pane's width; none passes the bytes as they are.
    pane: Option<usize>,
    /// The width that the far end believes it has, when it differs.
    far_width: Option<usize>,
    /// After these many lines, the pane draws each of its rows again.
    repaint_at: Vec<usize>,
    /// After these many bytes, the pane draws its status line.
    status_at: Vec<usize>,
    /// The near end's writes that are lost, by their number.
    lose: Vec<usize>,
}

/// A terminal of `cols` by `rows` that draws what the far end writes.
struct Pane {
    cols: usize,
    rows: usize,
    row: usize,
    /// The text of each row on the screen, the cursor's last.
    screen: VecDeque<Vec<u8>>,
    lines: usize,
    bytes: usize,
    /// Inside an escape sequence of the far end, which the pane obeys and
    /// never passes.
    escape: bool,
    damage: Damage,
}

impl Pane {
    fn new(cols: usize, damage: Damage) -> Pane {
        let screen = VecDeque::from([Vec::new()]);
        Pane { cols, rows: 23, row: 1, screen, lines: 0, bytes: 0, escape: false, damage }
    }

    fn write(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in bytes {
            self.bytes += 1;
            if self.damage.status_at.first().is_some_and(|&at| self.bytes >= at) {
                self.damage.status_at.remove(0);
                out.extend_from_slice(b"\x1b7\x1b[24;1H\x1b[30;42m[t831] 0:podssh* \"far\" 12:00\x1b[0m\x1b8");
            }
            if self.escape {
                self.escape = !(0x40..=0x7e).contains(&b) || b == b'[';
                continue;
            }
            match b {
                0x1b => self.escape = true,
                b'\n' => self.newline(&mut out),
                // The pane places its cursor itself; ZDLE and each other
                // control byte is the pane's to obey, and never passes.
                b if b < 0x20 || b == 0x7f => {}
                b => {
                    if self.screen.back().is_some_and(|line| line.len() == self.cols) {
                        self.newline(&mut out);
                    }
                    let line = self.screen.back_mut().expect("a row");
                    if line.is_empty() {
                        out.extend_from_slice(format!("\x1b[{};1H", self.row).as_bytes());
                    }
                    line.push(b);
                    out.push(b);
                }
            }
        }
        out
    }

    fn newline(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"\x1b[K");
        if self.row == self.rows {
            out.extend_from_slice(b"\r\n");
            self.screen.pop_front();
        } else {
            self.row += 1;
        }
        self.screen.push_back(Vec::new());
        self.lines += 1;
        if self.damage.repaint_at.first().is_some_and(|&at| self.lines >= at) {
            self.damage.repaint_at.remove(0);
            out.extend_from_slice(b"\x1b[H\x1b[2J");
            for (i, line) in self.screen.iter().enumerate() {
                out.extend_from_slice(format!("\x1b[{};1H", i + 1).as_bytes());
                out.extend_from_slice(line);
                out.extend_from_slice(b"\x1b[K");
            }
        }
    }
}

/// The far end of the test and what it took or gave.
struct Far {
    codec: Transfer,
    data: Vec<u8>,
    got: Vec<u8>,
    ended: Option<Ended>,
}

impl Far {
    fn act(&mut self, events: Vec<Event>) {
        let mut queue = VecDeque::from(events);
        while let Some(event) = queue.pop_front() {
            match event {
                Event::NeedData { offset, max } => {
                    let at = offset as usize;
                    let end = (at + max).min(self.data.len());
                    let chunk = self.data[at..end].to_vec();
                    self.codec.supply(&chunk);
                }
                Event::Offer { .. } => self.codec.take(),
                Event::Write { bytes, .. } => self.got.extend(bytes),
                Event::Verified { .. } => self.codec.kept(),
                Event::End { ended, .. } => self.ended = Some(ended),
                _ => {}
            }
            queue.extend(self.codec.events());
        }
    }
}

/// The bytes of a file of the test: the same for each run.
fn data(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x2545_f491;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

/// One file across, `download` from the far end or to it: what the near
/// terminal showed, and the far end.
fn cross(damage: &Damage, download: bool, answer: &[u8], data: Vec<u8>) -> (String, Far) {
    let t0 = Instant::now();
    let mut t = t0;
    let id = [0x5a, 0x17, 0x00, 0x42, 0x99, 0x01, 0xfe, 0x30];
    let codec = if download {
        let info = FileInfo { name: "d.bin".into(), size: data.len() as u64, mode: Some(0o640), mtime: Some(1) };
        Transfer::far_send(info, id, t)
    } else {
        Transfer::far_receive(id, t)
    };
    let mut far = Far { codec, data, got: Vec::new(), ended: None };
    let pane_cols = damage.pane.unwrap_or(80);
    far.codec.set_width(damage.far_width.unwrap_or(pane_cols));
    let mut pane = damage.pane.map(|cols| Pane::new(cols, damage.clone()));
    let mut z = Zmodem::new();
    let (mut screen, mut to_near) = (Vec::new(), VecDeque::new());
    let (mut answered, mut writes) = (false, 0usize);
    let reads = [7usize, 64, 1, 300, 4096, 13];
    for turn in 0..2_000_000usize {
        let mut moved = false;
        let bytes = far.codec.poll_output(t);
        if !bytes.is_empty() {
            to_near.extend(match pane.as_mut() {
                Some(pane) => pane.write(&bytes),
                None => bytes,
            });
        }
        if !to_near.is_empty() {
            let n = reads[turn % reads.len()].min(to_near.len());
            let read: Vec<u8> = to_near.drain(..n).collect();
            screen.extend(z.output(&read, t));
            moved = true;
        }
        if !answered && z.busy() && !z.transferring() {
            assert!(z.keys(answer.to_vec(), t).is_empty());
            answered = true;
            moved = true;
        }
        let taken = z.take(t);
        z.written();
        screen.extend(taken.screen);
        if !taken.server.is_empty() {
            writes += 1;
            moved = true;
            if !damage.lose.contains(&writes) {
                let events = far.codec.feed(&taken.server, t);
                far.act(events);
            }
        }
        if far.ended.is_some() && !z.busy() && to_near.is_empty() {
            return (String::from_utf8_lossy(&screen).into_owned(), far);
        }
        if moved {
            t += Duration::from_millis(1);
        } else {
            // Nothing moves: the next wait of either end passes at once.
            let due = [z.deadline(), far.codec.deadline()].into_iter().flatten().min();
            t = due.map_or(t + Duration::from_millis(10), |due| due.max(t + Duration::from_millis(1)));
            z.tick(t);
            let events = far.codec.tick(t);
            far.act(events);
        }
        assert!(t < t0 + Duration::from_secs(600), "no end in 600 s of the test's clock");
    }
    panic!("the transfer did not end");
}

/// Each damage of the table, each way: the file crosses whole, both ends
/// end with it kept, the trigger and the frames never show, and a damaged
/// frame goes again.
#[test]
fn a_file_crosses_whole_through_a_terminal_that_draws_its_own_screen() {
    let rows: Vec<(&str, Damage)> = vec![
        ("a pty that passes each byte", Damage::default()),
        ("tmux's pane of 80 columns", Damage { pane: Some(80), ..Damage::default() }),
        ("a far end wider than its pane", Damage { pane: Some(80), far_width: Some(120), ..Damage::default() }),
        ("a repaint of the screen", Damage { pane: Some(80), repaint_at: vec![60, 400], ..Damage::default() }),
        ("the status line in a frame", Damage { pane: Some(80), status_at: vec![3000, 50_000], ..Damage::default() }),
        ("a write of the near end lost", Damage { pane: Some(80), lose: vec![3, 6], ..Damage::default() }),
    ];
    for (name, damage) in rows {
        for download in [true, false] {
            let way = if download { "download" } else { "upload" };
            let case = format!("{name}, {way}");
            let dir = scratch(&format!("damage-{}-{way}", name.len()));
            let file = data(150_000);
            let (screen, far) = if download {
                let answer = format!("{}\r", dir.display()).into_bytes();
                let (screen, far) = cross(&damage, true, &answer, file.clone());
                assert_eq!(std::fs::read(dir.join("d.bin")).ok().as_deref(), Some(&file[..]), "{case}");
                assert_eq!(names(&dir), ["d.bin"], "{case}: no temporary file");
                (screen, far)
            } else {
                let path = dir.join("u.bin");
                std::fs::write(&path, &file).expect("a file");
                let answer = format!("{}\r", path.display()).into_bytes();
                let (screen, far) = cross(&damage, false, &answer, Vec::new());
                assert!(far.got == file, "{case}: the far end got {} of {} bytes", far.got.len(), file.len());
                (screen, far)
            };
            assert_eq!(far.ended, Some(Ended::Done), "{case}: {screen:?}");
            let line = if download { "received " } else { "sent u.bin (150000 bytes" };
            assert!(screen.contains(line), "{case}: {screen:?}");
            for frame in ["#PODSSH-TX", "#DATA:", "#ACKN:", "#HELO:"] {
                assert!(!screen.contains(frame), "{case}: {frame} shows");
            }
            let damaged = !damage.repaint_at.is_empty() || !damage.status_at.is_empty();
            if download && damaged {
                assert!(screen.contains("damaged frames went again"), "{case}: {screen:?}");
            }
        }
    }
}
