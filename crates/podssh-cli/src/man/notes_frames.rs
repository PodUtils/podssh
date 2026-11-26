//! The note of `--frames` (T-303) for `podssh ssh`, apart from the others so
//! that each file stays short.

pub const SSH_FRAMES: &str = "--frames shows the far end's latest screen in place of each byte of its output. It \
     works only to podssh serve with a pty. The far end keeps a model of its screen, and sends the difference of \
     screens, at most one frame each half round trip. A frame goes no sooner than 20 ms after the last, and waits \
     no longer than 250 ms. Under a flood over a slow link, at most two frames wait in the link. Ctrl-C then \
     shows its prompt without the bytes of the flood before it. Each key goes as before. A frame skips output, so \
     the terminal's own scrollback gets none of the session's lines. Read back with a pager at the far end. The \
     lines on the terminal at the start move up into its scrollback. Another server refuses the ask: podssh says \
     so in one line, and the session shows each byte. A shell with frames is not kept, so ~d is refused. \
     --attach, --expect, --sudo and --su show each byte, and so does a far end that shares its shell; one line \
     says so. ZMODEM and a copy to the clipboard do not cross: a frame carries the screen alone. The far end \
     itself answers a program that asks its terminal for the cursor's place or the device's attributes. The \
     window's title and the bell cross with a frame. After a line of podssh's own on the terminal, the next frame \
     draws the whole screen again. For the frames the far end holds at most five copies of the screen, each some \
     60 KiB at 80 by 24. --frames and --predict cannot be used together (exit 64). A Windows console that takes \
     no VT sequences ends the session with one line (exit 255). So do bytes of the far end that are no frame.";
