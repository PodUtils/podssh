//! The notes of a unit of systemd read before it is installed, and of a
//! system unit that runs as a named user (T-709), for `node` and `serve`,
//! apart from the others so that each file stays short. The settings of the
//! unit are named without their values, which the notes' check would read
//! as keywords of ssh.

/// The node's side: `--print-unit`, and `--install --system --run-as`.
pub(super) const NODE: &str = "--print-unit prints the unit that --install would write, on stdout, and writes \
     nothing. It does so on any system, so that the unit is read before it is installed. It checks what \
     --install checks first: a TARGET that the node refuses gives 64. A user unit of a pair not stored gives 78. \
     With --system --run-as USER, it is the system unit. --install --system --run-as USER writes \
     /etc/systemd/system/podssh-node-NAME.service, then runs systemctl daemon-reload, enable and restart. It \
     probes first, in this order: root (else 77), systemd as the service manager (/run/systemd/system, else 69), \
     USER in /etc/passwd (else 69), and USER's cache of podssh (else 69). USER is no root (64). The unit runs as \
     USER, with HOME, XDG_CACHE_HOME and XDG_CONFIG_HOME in USER's home. So the node reads the pair and the keys \
     that USER's own runs keep: podssh relay pair NAME, run as USER, makes them. The file of its variables is \
     /var/lib/podssh-node-NAME/node-NAME.env, of mode 0600 and USER's, in the unit's state directory. Each user \
     may read a unit, so no token goes in it. The unit is hardened. It sets NoNewPrivileges, an empty \
     CapabilityBoundingSet, ProtectSystem strict, and ProtectHome tmpfs with USER's cache bound in. It sets \
     PrivateTmp, PrivateDevices, ProtectKernel*, and RestrictAddressFamilies to inet, inet6 and unix sockets. It \
     sets SystemCallFilter to the set of a system service, LockPersonality and MemoryDenyWriteExecute. --exit, \
     --routes and --iroh add netlink sockets, by which the kernel gives this host's own addresses. A comment of \
     the unit names that line. A roost (--sshd) relaxes nothing. --uninstall --system, as root, removes the unit, \
     stopped first, and the file of the variables with its lock.";

/// serve's side: `--print-unit` alone, as serve installs nothing.
pub(super) const SERVE: &str = "serve NAME --print-unit prints a unit of systemd that runs serve NAME with \
     these flags, each file by its absolute path, and writes nothing. It is a user unit; with --system --run-as \
     USER, a system unit that runs as USER, with HOME and the login shell of USER's passwd entry. Its sessions \
     run the user's programs, as sshd's do. So the unit leaves out each line of the node's hardening that would \
     change what a session may do. A comment names each, with why. It keeps ProtectKernel*, ProtectClock, \
     ProtectHostname, ProtectControlGroups and RestrictRealtime. serve installs nothing itself: put the unit in \
     place by hand.";
