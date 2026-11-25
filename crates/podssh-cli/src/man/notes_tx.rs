//! The notes of `podssh tx` (T-831), the far end of the 7-bit envelope,
//! apart from the others so that each file stays short.

pub const TX: &[&str] = &[
    "podssh tx moves one file through the terminal of a podssh ssh session, for a path where ZMODEM breaks. tmux \
     and other programs that draw a terminal of their own sit between the shell and the session's pty. They \
     repaint what passes, and drop the bytes of ZMODEM's frames. Type it in the shell at the far end of the session; it needs \
     podssh there too, the same static binary. podssh tx send FILE sends FILE to podssh ssh at \
     the near end, which asks where it goes, as it asks for sz. podssh tx receive [DIR] waits for a file from \
     the near end, which asks which file to send, as it asks for rz; the file comes into DIR, the current \
     directory with none. podssh tx receive never replaces a name that DIR has: it skips that file and exits 75. At the \
     near end, a name that exists asks Replace it? [y/N], and only y replaces it.",
    "Each byte that crosses is printable ASCII, CR or LF. A first line starts the transfer, and the near \
     end removes it from its screen. Then come frames of base64 with a CRC-32 each. The near end reads them back \
     from what the terminal draws, also wrapped, repainted or cut by escape sequences. One frame waits for its answer \
     at a time, and goes again after a silence; a frame that comes damaged is dropped and sent again. The file \
     comes as podssh cp writes a copy: to .NAME.podssh-RANDOM.part beside its name, then the SHA-256 and the \
     size are compared with the sender's, then a rename gives it its name. Nothing listens and nothing \
     connects: the session's own terminal carries it all.",
    "podssh tx sets its terminal raw while it runs, and needs one of 48 columns at least. Each wait for the \
     other end has 20 s, and the first one 120 s, for the question at the near end. Ctrl-C at the near end, or \
     five Ctrl-X typed in a row, stops the transfer at both ends. No file that did not end is kept. A \
     question at the near end has no limit: the near end tells the far end that it waits. A transfer that the near \
     end never took, or that Ctrl-C stopped, leaves its lines on the screen; clear it with clear or Ctrl-L. After the file is \
     kept, podssh tx receive waits 25 s more for a confirmation that the terminal lost; Ctrl-C or Ctrl-D \
     ends that wait. It exits 0 when the file was kept, with one line on stderr. It also exits 0 when podssh tx \
     send sent the file and its SHA-256 and no confirmation came, which the line says. It exits 64 with no terminal, one too \
     narrow, or a word wrong; 65 when the size or the SHA-256 differs, or the other end broke the protocol; 66 when FILE or DIR \
     cannot be read; 73 when the file that came cannot be created in DIR, written or kept; 75 when it was refused, skipped, \
     cancelled or got no answer in time. The near end is podssh ssh with a pty and a local terminal; with \
     PODSSH_ZMODEM set to off, or through a control master, it watches for neither ZMODEM nor this.",
];
