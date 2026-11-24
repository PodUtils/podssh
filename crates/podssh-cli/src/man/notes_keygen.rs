//! The notes of `podssh keygen`, apart from the others so that each file
//! stays short.

pub const KEYGEN: &[&str] = &[
    "The keys are in the formats of OpenSSH. The private key has mode 0600, as the keys of OpenSSH have. On Windows \
     it has an access list of its own that lets in only the user, SYSTEM and the Administrators, as OpenSSH's keys \
     do; a new key never replaces a file that exists. The public key goes to FILE.pub, which others may read and not \
     change. podssh prints the SHA-256 fingerprint.",
    "podssh keygen -p -f FILE changes the passphrase of a key: podssh asks for the old one, then for the new \
     one two times. podssh keygen -c -f FILE changes its comment, to -C COMMENT or to one that podssh asks \
     for, in the key and in FILE.pub. The file is replaced only with the same key, read back and compared \
     first, and no copy of the old file is kept. A key in another format that podssh ssh -i reads is written \
     in the format of OpenSSH. -P '' is for a key with no passphrase; a passphrase given with -P is refused.",
    "podssh keygen -F HOST prints the lines of HOST in known_hosts (-f FILE, else ~/.ssh/known_hosts), as ssh-keygen \
     does. -R HOST removes them, and -H hashes each host name; a host on another port is [HOST]:PORT. -R and -H keep \
     the old text as FILE.old, and the new text takes the file's place whole, with its mode. -R keeps a line \
     that names the host through a wildcard, as its key is for other hosts too.",
    "podssh keygen -Y sign -f KEY -n NAMESPACE FILE signs FILE to FILE.sig, or standard input to standard output. \
     This is as ssh-keygen -Y sign does for git; the agent signs when it holds the key of KEY (-U: the agent alone). \
     -Y verify -f SIGNERS -I PRINCIPAL -n NAMESPACE -s FILE.sig checks the data on standard input against SIGNERS, \
     an allowed-signers file. It says Good or Could not verify signature. (exit 1). -Y check-novalidate, \
     find-principals and match-principals are those of ssh-keygen. A signature never replaces a file.",
    "podssh keygen -Y sign -f KEY-cert.pub signs with that certificate and the private key KEY (or the agent's), as \
     ssh-keygen does; -f KEY signs with the plain key even with KEY-cert.pub beside it. A cert-authority line of \
     SIGNERS allows such a signature when its key is the certificate's CA. The certificate must be a user \
     certificate, valid at the time, that lists the principal of -I; a plain line of the key does not allow it.",
    "podssh keygen -s CA -I ID [-n NAMES] [-V INTERVAL] [-z SERIAL] [-O OPTION] [-h] FILE.pub certifies each key \
     into FILE-cert.pub. This is as ssh-keygen -s does, and -U says that the CA is in the agent. podssh keygen -L -f \
     FILE prints a certificate. -V here is a validity, such as +52w or 20260101:20270101; the version is podssh -V. \
     A certificate replaces the one that is there, as OpenSSH's does, and keeps its mode; a new one is 0644, as a \
     certificate is public.",
    "podssh keygen -e -m FORMAT -f FILE prints the public key of FILE as RFC4716 (the default), PKCS8 or \
     PEM; -i -m FORMAT -f FILE prints such a key as a line of OpenSSH. -m PEM or PKCS8 with a new key or -p \
     writes the private key in that format. An Ed25519 key has a form of RFC4716 only. -y and -l read a key \
     in each format that podssh ssh -i reads. -l on a private key shows the comment of FILE.pub, when that is \
     the same key, as ssh-keygen -l does: a key with a passphrase keeps its comment encrypted.",
    "podssh keygen -t ed25519-sk or -t ecdsa-sk makes a key in a security key (FIDO2), as ssh-keygen does: the \
     device keeps the key, and the file holds the device's handle of it, in the format of OpenSSH. Each signature \
     needs a touch of the device, within 30 s. -O resident keeps the key in the device, -O verify-required asks the \
     device's PIN at each use, and -O no-touch-required signs with no touch. -O application=ssh:NAME and -O \
     user=NAME name the key. On Linux podssh reaches the device through /dev/hidraw (-O device=PATH names one); on \
     Windows, Windows shows its own dialog. With no device that podssh may reach, it says why, asks nothing and \
     writes nothing (exit 1). PODSSH_SK_DEVICE set to none turns security keys off.",
    "podssh asks for the passphrase two times, on the terminal or through SSH_ASKPASS. -N '' makes a key \
     with no passphrase. A passphrase given with -N is refused, because each process on the host can \
     read a command line. With no terminal and no SSH_ASKPASS, podssh stops at once and names -N ''.",
    "DSA keys are refused: OpenSSH 10 removed them. The default comment is USER@HOST, with the local \
     user's name as podssh ssh takes it: PODSSH_USER, USER, LOGNAME or USERNAME, else the user database's \
     entry (see ENVIRONMENT).",
];

/// The note of `podssh status --keys`, beside keygen's, as both show the
/// public half of a key: the notes of status name it.
pub const STATUS_KEYS: &str = "With --keys, the line's keys lists the public part of each key that podssh keeps on \
     this host. It is read with no connection, and no key is made. Each entry has role, label, path, type, public, \
     fingerprint, iroh and state. role is client, the key that reaches a node, or node, one for each label. acme is \
     the account of podssh relay serve at each certificate authority; warp is the device of a warp:// destination. \
     net_owner, when this host holds a net, is the owner's key from the net's document. Its path is the key of ~/.ssh \
     whose .pub file holds that key, which podssh does not open. state is present, absent or unreadable, with error, \
     which names the file and never its text. public is a line of OpenSSH for an Ed25519 key, the JWK of an account, \
     and the base64 of a device's SubjectPublicKeyInfo. fingerprint is the SHA-256 fingerprint that podssh keygen -l \
     prints, or an account's thumbprint. iroh is an Ed25519 key in iroh's hex, the node's name on the iroh road. With \
     PODSSH_CACHE_DIR=none, each key is absent. --keys with a destination is refused (64); without --keys, keys is \
     null.";
