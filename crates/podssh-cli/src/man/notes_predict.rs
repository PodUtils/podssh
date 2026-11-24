//! The note of `--predict` (T-160) for `podssh ssh`, apart from the others so
//! that each file stays short.

pub const SSH_PREDICT: &str = "--predict shows each key that you type at once, underlined, where the far end \
     will echo it. When the echo comes, the underline goes. It works only to podssh serve with a pty, which tells \
     the client which keys reached the pty and whether the pty echoes. A kept shell tells the client that has it \
     now. A shell shared by name tells its owner and each seat that types, each of its own keys; a seat that \
     watches gets nothing. Another server refuses the ask, and -v says \
     so. A Windows console that takes no VT sequences shows no guess either, and -v says so. Guesses start to \
     show at a round trip of 120 ms, and stop below 80 ms. The guesses are printable \
     characters, Backspace and the left and right arrows, on the cursor's row. After each other key, a paste or a \
     wrong guess, nothing shows until the far end echoes a new guess. A line that the pty \
     reads with no echo, as for a password, shows no guess at all. A line of podssh's own on the terminal, an \
     escape, ZMODEM or a far end that counts wrong ends the guesses for the session.";
