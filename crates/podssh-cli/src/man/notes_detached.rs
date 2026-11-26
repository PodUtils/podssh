//! The notes of `podssh detached` (T-392), apart from the others so that
//! each file stays short.

pub const DETACHED: &[&str] = &[
    "podssh detached list writes a line for each run in the background that this user started with -f or --detach. \
     The runs are of podssh ssh, pipe and node, by their name: the name, its state (running; running, its supervisor \
     gone, for a run of --restart whose supervisor ended; or ended), its pid and its words, with a tab between them. \
     An ended run's state also names its exit code, where the run wrote one. A record that cannot be read is listed \
     as ended, its record unreadable. \
     A run's name is its --detach-name, else its verb and its pid (ssh-4242), which no other running run has. So a \
     run with no name is never refused. With no run, stdout stays empty and one line on stderr says that no run is \
     known and names the directory read (none with -q). list --json writes one object instead: runs (each with its \
     name, state, pid, a number or null, and words; [] for none) and dir, the directory read (null with no directory \
     of the cache). Each run's exit is a number, or null where the run wrote none. The exit is 0.",
    "Each run holds the lock of its name, NAME.lock in the directory detached of the cache (see FILES), from \
     before its connection to its end; with --restart its supervisor holds it, so that each restart keeps it, \
     and the run that it starts holds NAME.run.lock. A second start of a name that runs refuses with 75 before \
     it connects, and names the pid that runs; so does a start of a name whose run of --restart outlived its \
     supervisor. The system lets a lock go when its process ends, however it ends, so a run that crashed \
     leaves no name taken. With PODSSH_CACHE_DIR set to none there is no lock: a line says so, and the run goes \
     on, as a run that never starts locks its server out.",
    "status NAME writes the run's name, state, pid, verb, words, log and start, one to a line. With --restart, the \
     pid is its supervisor's, and its run's is on a line of its own. A run of --restart also has the age of its last \
     heartbeat (see podssh ssh); it exits 0 when the run runs, 69 when it does not. stop NAME sends SIGTERM to the \
     holder of the name (a supervisor passes it to its run). After 10 s it sends SIGKILL to each holder still there, \
     the supervisor first; on Windows it ends each at once (TerminateProcess), the supervisor first. It exits 0 once \
     each lock of the name is free, and 69 when nothing of that name runs. It exits 75 when a lock is still held \
     after the kill. A run writes its end into its record as it exits: status then gives the time of the end and the \
     exit code. A run that was killed writes neither, and status shows a dash for each. A record that cannot be read \
     is said so, with its path, and the exit is 69.",
    "Each reads the locks, never a pid alone: a run's record (NAME.json) stays after it ended, and the system \
     gives its pid to another process, which a signal would reach. A pid is sent a signal only while the lock of \
     its run is held, and it is the pid that the holder wrote there.",
];
