//! The terminal modes of RFC 4254 (section 8) and their termios fields: one
//! table, read one way by the client to send its terminal's settings, and
//! the other way by `podssh serve` to set a pty's slave (T-110), so that the
//! two sides never drift apart.

use russh::Pty;

/// Where a mode lives in termios.
#[derive(Debug, Clone, Copy)]
enum Field {
    /// A special character, by its index in `c_cc`.
    Cc(usize),
    Input(libc::tcflag_t),
    Local(libc::tcflag_t),
    Output(libc::tcflag_t),
    Control(libc::tcflag_t),
    /// The character size: one value of `CSIZE`.
    CharSize(libc::tcflag_t),
    InputSpeed,
    OutputSpeed,
}

use Field::{Cc, CharSize, Control, Input, InputSpeed, Local, Output, OutputSpeed};

/// Each mode, in the order that the client sends them.
const TABLE: &[(Pty, Field)] = &[
    (Pty::VINTR, Cc(libc::VINTR)),
    (Pty::VQUIT, Cc(libc::VQUIT)),
    (Pty::VERASE, Cc(libc::VERASE)),
    (Pty::VKILL, Cc(libc::VKILL)),
    (Pty::VEOF, Cc(libc::VEOF)),
    (Pty::VEOL, Cc(libc::VEOL)),
    (Pty::VEOL2, Cc(libc::VEOL2)),
    (Pty::VSTART, Cc(libc::VSTART)),
    (Pty::VSTOP, Cc(libc::VSTOP)),
    (Pty::VSUSP, Cc(libc::VSUSP)),
    (Pty::VREPRINT, Cc(libc::VREPRINT)),
    (Pty::VWERASE, Cc(libc::VWERASE)),
    (Pty::VLNEXT, Cc(libc::VLNEXT)),
    (Pty::VDISCARD, Cc(libc::VDISCARD)),
    (Pty::IGNPAR, Input(libc::IGNPAR)),
    (Pty::PARMRK, Input(libc::PARMRK)),
    (Pty::INPCK, Input(libc::INPCK)),
    (Pty::ISTRIP, Input(libc::ISTRIP)),
    (Pty::INLCR, Input(libc::INLCR)),
    (Pty::IGNCR, Input(libc::IGNCR)),
    (Pty::ICRNL, Input(libc::ICRNL)),
    (Pty::IXON, Input(libc::IXON)),
    (Pty::IXANY, Input(libc::IXANY)),
    (Pty::IXOFF, Input(libc::IXOFF)),
    (Pty::IMAXBEL, Input(libc::IMAXBEL)),
    (Pty::ISIG, Local(libc::ISIG)),
    (Pty::ICANON, Local(libc::ICANON)),
    (Pty::ECHO, Local(libc::ECHO)),
    (Pty::ECHOE, Local(libc::ECHOE)),
    (Pty::ECHOK, Local(libc::ECHOK)),
    (Pty::ECHONL, Local(libc::ECHONL)),
    (Pty::NOFLSH, Local(libc::NOFLSH)),
    (Pty::TOSTOP, Local(libc::TOSTOP)),
    (Pty::IEXTEN, Local(libc::IEXTEN)),
    (Pty::ECHOCTL, Local(libc::ECHOCTL)),
    (Pty::ECHOKE, Local(libc::ECHOKE)),
    (Pty::PENDIN, Local(libc::PENDIN)),
    (Pty::OPOST, Output(libc::OPOST)),
    (Pty::ONLCR, Output(libc::ONLCR)),
    (Pty::OCRNL, Output(libc::OCRNL)),
    (Pty::ONOCR, Output(libc::ONOCR)),
    (Pty::ONLRET, Output(libc::ONLRET)),
    (Pty::CS7, CharSize(libc::CS7)),
    (Pty::CS8, CharSize(libc::CS8)),
    (Pty::PARENB, Control(libc::PARENB)),
    (Pty::PARODD, Control(libc::PARODD)),
    (Pty::TTY_OP_ISPEED, InputSpeed),
    (Pty::TTY_OP_OSPEED, OutputSpeed),
];

/// The modes that only Linux's termios has.
#[cfg(target_os = "linux")]
const LINUX: &[(Pty, Field)] = &[
    (Pty::IUCLC, Input(libc::IUCLC)),
    (Pty::IUTF8, Input(libc::IUTF8)),
    (Pty::XCASE, Local(libc::XCASE)),
    (Pty::OLCUC, Output(libc::OLCUC)),
];

#[cfg(not(target_os = "linux"))]
const LINUX: &[(Pty, Field)] = &[];

/// A special character that is off: 0 in Linux's termios, 255 in the BSDs'
/// and on the wire.
#[cfg(target_os = "linux")]
const DISABLED: libc::cc_t = 0;
#[cfg(not(target_os = "linux"))]
const DISABLED: libc::cc_t = 0xff;

/// The speed that the client sends: a pty has none, and 38400 is what
/// OpenSSH's client sends for one.
const SPEED: u32 = 38400;

fn fields() -> impl Iterator<Item = (Pty, Field)> {
    TABLE.iter().chain(LINUX).copied()
}

/// The modes of `t`, as the client sends them.
pub fn encode(t: &libc::termios) -> Vec<(Pty, u32)> {
    fields().map(|(pty, field)| (pty, read(t, field))).collect()
}

fn read(t: &libc::termios, field: Field) -> u32 {
    let flag = |set: libc::tcflag_t, bit: libc::tcflag_t| u32::from(set & bit != 0);
    match field {
        // A disabled special character is 0 in termios and 255 on the wire.
        Cc(i) => match t.c_cc[i] as u32 {
            0 => 255,
            v => v,
        },
        Input(bit) => flag(t.c_iflag, bit),
        Local(bit) => flag(t.c_lflag, bit),
        Output(bit) => flag(t.c_oflag, bit),
        Control(bit) => flag(t.c_cflag, bit),
        CharSize(size) => u32::from(t.c_cflag & libc::CSIZE == size),
        InputSpeed | OutputSpeed => SPEED,
    }
}

/// Set `modes` on `t`, as a client asked for them. A mode that this table
/// does not have, or a value that does not fit, is passed over and
/// returned: a client of another system sends modes that this one lacks.
pub fn apply(t: &mut libc::termios, modes: &[(Pty, u32)]) -> Vec<Pty> {
    let mut passed = Vec::new();
    for &(pty, value) in modes {
        let done = fields().find(|(p, _)| *p == pty).is_some_and(|(_, field)| write(t, field, value));
        if !done {
            passed.push(pty);
        }
    }
    passed
}

fn write(t: &mut libc::termios, field: Field, value: u32) -> bool {
    let set = |flags: &mut libc::tcflag_t, bit: libc::tcflag_t| {
        if value != 0 {
            *flags |= bit;
        } else {
            *flags &= !bit;
        }
    };
    match field {
        Cc(i) => {
            t.c_cc[i] = match value {
                255 => DISABLED,
                v if v < 255 => v as libc::cc_t,
                _ => return false,
            };
        }
        Input(bit) => set(&mut t.c_iflag, bit),
        Local(bit) => set(&mut t.c_lflag, bit),
        Output(bit) => set(&mut t.c_oflag, bit),
        Control(bit) => set(&mut t.c_cflag, bit),
        // Off says nothing of the size: the other size's mode sets it.
        CharSize(size) => {
            if value != 0 {
                t.c_cflag = (t.c_cflag & !libc::CSIZE) | size;
            }
        }
        InputSpeed | OutputSpeed => {
            let Some(speed) = speed(value) else { return false };
            // SAFETY: both take a termios that this function's caller owns.
            let rc = unsafe {
                if matches!(field, InputSpeed) {
                    libc::cfsetispeed(t, speed)
                } else {
                    libc::cfsetospeed(t, speed)
                }
            };
            return rc == 0;
        }
    }
    true
}

/// The termios speed of `baud`, for the speeds that each Unix has.
fn speed(baud: u32) -> Option<libc::speed_t> {
    Some(match baud {
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeroed() -> libc::termios {
        // SAFETY: an all-zero termios is a valid value of the struct.
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn each_mode_comes_back_as_it_was_set() {
        let mut t = zeroed();
        let asked = [
            (Pty::VINTR, 3),
            (Pty::VERASE, 8),
            (Pty::VEOL, 255),
            (Pty::ICRNL, 1),
            (Pty::ECHO, 0),
            (Pty::ICANON, 1),
            (Pty::ISIG, 1),
            (Pty::OPOST, 1),
            (Pty::ONLCR, 1),
            (Pty::CS8, 1),
            (Pty::PARENB, 0),
        ];
        assert!(apply(&mut t, &asked).is_empty());
        let back = encode(&t);
        for (pty, value) in asked {
            let got = back.iter().find(|(p, _)| *p == pty).map(|(_, v)| *v);
            assert_eq!(got, Some(value), "{pty:?}");
        }
        assert_eq!(t.c_cc[libc::VEOL], DISABLED, "255 on the wire is a disabled character");
        assert_eq!(t.c_cflag & libc::CSIZE, libc::CS8);
    }

    #[test]
    fn a_mode_turned_off_clears_its_bit_alone() {
        let mut t = zeroed();
        t.c_lflag = libc::ECHO | libc::ICANON;
        apply(&mut t, &[(Pty::ECHO, 0)]);
        assert_eq!(t.c_lflag, libc::ICANON);
    }

    #[test]
    fn what_does_not_fit_is_passed_over_and_named() {
        let mut t = zeroed();
        let passed = apply(&mut t, &[(Pty::VINTR, 300), (Pty::VFLUSH, 1), (Pty::TTY_OP_ISPEED, 12345)]);
        assert_eq!(passed, vec![Pty::VINTR, Pty::VFLUSH, Pty::TTY_OP_ISPEED]);
        assert_eq!(t.c_cc[libc::VINTR], 0, "a value past 255 changes nothing");
    }

    // One speed for both: musl keeps a single speed, and sets the output's
    // for an input's.
    #[test]
    fn the_speed_is_set_where_it_is_one_of_each_unix() {
        let mut t = zeroed();
        assert!(apply(&mut t, &[(Pty::TTY_OP_ISPEED, 9600), (Pty::TTY_OP_OSPEED, 9600)]).is_empty());
        // SAFETY: both read a termios that this test owns.
        assert_eq!(unsafe { libc::cfgetispeed(&t) }, libc::B9600);
        assert_eq!(unsafe { libc::cfgetospeed(&t) }, libc::B9600);
    }

    #[test]
    fn the_client_sends_each_mode_of_the_table_once() {
        let sent = encode(&zeroed());
        assert_eq!(sent.len(), TABLE.len() + LINUX.len());
        assert_eq!(sent[0], (Pty::VINTR, 255), "a zero special character is sent as disabled");
        for (pty, _) in &sent {
            assert_eq!(sent.iter().filter(|(p, _)| p == pty).count(), 1, "{pty:?}");
        }
    }
}
