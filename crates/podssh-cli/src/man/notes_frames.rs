//! The note of `--frames` (T-303) for `podssh ssh`, apart from the others so
//! that each file stays short.

pub const SSH_FRAMES: &str = "--frames shows the far end's latest screen in place of each byte of its output. It \
     works only to podssh serve with a pty. The far end keeps a model of its screen, and sends the difference of \
     screens, at most one frame each half round trip. A frame goes no sooner than 20 ms after the last, and waits no \
     longer than 250 ms. Under a flood over a slow link, at most two frames wait in the link. Ctrl-C then shows its \
     prompt without the bytes of the flood before it. Each key goes as before. A frame skips output, so the \
     terminal's own scrollback gets none of the session's lines. --frames-scroll is --frames with them: a frame also \
     carries the lines that left the top of the screen, at most one screen of them. podssh moves them into the \
     terminal's own scrollback before it draws the screen. Under a flood, one dim line says how many lines were \
     skipped in between. An older podssh serve sends no such lines. The lines on the terminal at the start move up \
     into its scrollback. --record keeps what was drawn on the terminal, and podssh play shows it again. Another \
     server refuses the ask: podssh says so in one line, and the session shows each byte. A shell with frames is kept \
     as any shell, and podssh serve keeps the model of its screen with it. --attach with --frames gets the whole \
     screen first, then its changes; a client without --frames gets the bytes. --expect, --sudo and --su show each \
     byte, and so does a far end that shares its shell by name; one line says so. ZMODEM and a copy to the \
     clipboard do not cross: a frame carries the screen alone. The far end itself answers a program that asks its \
     terminal for the cursor's place or the device's attributes. \
     The window's title and the bell cross with a frame. After a line of podssh's own on the terminal, the next \
     frame draws the whole screen again. For the frames the far end holds at most five copies of the screen, each \
     some 60 KiB at 80 by 24. With --frames-scroll it also keeps the text of one screen of lines. A kept \
     shell holds its model for its life, also with no client. With \
     --predict, the guesses are drawn over the frames' screen. A guess goes once a frame shows its echo, or the far \
     end's report finds it wrong. A Windows console that takes no VT sequences ends \
     the session with one line (exit 255). So do bytes of the far end that are no frame.";
