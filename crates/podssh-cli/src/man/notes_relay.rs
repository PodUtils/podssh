//! The notes of `podssh relay`: the pairs (T-083), the document (T-060),
//! the relay's own state (T-058) and the relay role (T-169, T-427), with its
//! certificate (T-447), and the pairing by a short code (T-086), apart from
//! the others so that each file stays short.

pub const RELAY: &[&str] = &[
    "podssh relay pair NAME makes a pair on the relay. It keeps it under the label NAME, in a private file of the \
     cache (see FILES). It prints the label and when the pair expires, 72 hours later, and never a token. With \
     --operator-file, the operator's part of the pair, its connect token alone, goes to FILE, a new file that only \
     its owner can read: give it to the operator by a channel that you trust. On stderr it says the way past the \
     expiry: in its last 24 hours, podssh relay pair NAME --operator-file NEW makes the next pair, which the node \
     takes at the expiry. NEW goes to each operator; stdout keeps its one line.",
    "A pair under NAME with more than 24 hours left is not replaced: stop it first with podssh relay \
     revoke NAME. In its last 24 hours, the next pair is made and takes its place in the store. A node of NAME \
     that runs takes it at the expiry, with no new start (see podssh node); the old pair can no longer be stopped, \
     and ends at its expiry. The default relay renews no pair, so each node of a pair needs the next one every 72 \
     hours. revoke stops the pair on the relay and deletes the stored copy; when the relay cannot be reached, the \
     copy is kept, because its stop token is the one way to stop the pair before it expires.",
    "podssh relay pair --renew NAME renews the pair stored under NAME at the relay that made it. The pair then has \
     72 hours from now, and never less than it had. It keeps the same three tokens, so that each operator's file \
     keeps working and the node goes on with no next pair; podssh relay serve renews, by the stop token, which the \
     pair's owner alone holds, as often as asked. It prints the label and the new expiry, and the store keeps it. \
     A relay that renews none (the default relay's contract has no such request: its answer is 404 or 405) is said \
     so, and the exit is 69. The message gives the next pair of the last 24 hours as the way; a refused stop token \
     (403) is a pair that was stopped or ended (77). --operator-file and --relay-host are refused with it (64): \
     the operator's file is never touched, and its end is asked of the relay once the file's has passed.",
    "podssh relay halt NAME keeps the operators of the pair stored under NAME out for a while. It works at podssh \
     relay serve, by the pair's stop token: each of its sessions ends once, with 1011 the pair's owner halted it. \
     Each operator's upgrade then hears 503 with the words of --reason TEXT and no Retry-After, until podssh relay \
     resume NAME. TEXT is one line of 200 bytes at most. That refusal spends no connect token of --once and no \
     token of one leg. The node keeps its socket, and so the pair's name: it hears that the pair is halted, a \
     frame that a node of before skips. It takes the next operator after the resume on the same socket, with no \
     new registration. podssh relay status NAME says halted, with the words, and its --json halted and \
     halt_reason. A second halt changes nothing (stdout: halted already, since when); resume, then halt, for new \
     words. The halt lives in the relay's memory alone: a restart of the relay serves the pair again. stdout has \
     one line, the label and halted, with the sessions that it closed, or resumed, or not halted. A relay that \
     halts none (the default relay's contract has no such request: 404 or 405) is said so, with podssh relay \
     revoke as the way to end the pair, and the exit is 69; a refused stop token (403) is a pair that was stopped \
     or ended (77); --relay-host is refused with them (64).",
    "podssh relay status NAME says whether the pair's node is online, its sessions, and when the pair expires. The \
     expiry is the relay's where it names one (podssh relay serve, whose renewal moves it), else the file's; in \
     its last 24 hours, how long is left too (expires in 5 h, at ...). On an operator's host, which stores no \
     pair, podssh relay status --pair-file FILE [NAME] asks the same of the pair in FILE. FILE may also be the \
     operator's part, which podssh relay pair --operator-file writes: the relay answers the status to its connect \
     token. NAME is then only the label shown (else FILE). With --json, the pair's state is one object: schema \
     (1), podssh, label, online, sessions, expires (RFC 3339), seconds_left and halted, for a check. It has \
     halt_reason where the pair's owner halted it with words (podssh relay halt).",
    "podssh relay pair NAME --code gives the operator's part by a short code in place of a file: the pair stored \
     under NAME while it has 10 minutes left, else the next pair, made first. It gives the node's key too \
     (node-NAME.key, made when it is missing). The code, such as 7-crossover-clockwork-adroitness, shows on this \
     run's terminal alone: on stderr when it is a terminal, else on the process's terminal, and with neither it is \
     refused (64) before anything is asked. It is never on stdout, in a log or in argv. Read it to the operator, \
     who runs podssh relay join NAME and types it: the two ends meet at a mailbox and run SPAKE2 keyed by the \
     whole code over it. They seal each later message with the key that it gave, so the mailbox learns nothing of \
     the code and changes nothing. The code lives 10 minutes and is used once: the first exchange spends it, \
     whatever its end, so a wrong code, or a guess, gets one try of its 24 bits. The operator's key comes back: \
     --allow FILE adds its line to the node's allowlist, which podssh node NAME --allow FILE reads again for each \
     session; with none, the pair's connect token is the node's door, and the key is said. stdout has one line, \
     the label, the operator's fingerprint and the pair's expiry; nobody within 10 minutes is 69, a wrong code 77.",
    "podssh relay join NAME takes the code at a prompt on the terminal, or as one line of stdin from a \
     pipe, never from argv. It finds the node's host at the first mailbox that lists the code's number. It checks \
     the pair that comes as a pair of the relay is checked. It pins the node's key under NAME in known-nodes: a \
     key that differs from the pin is refused (77), and nothing is kept. It gives this operator's key (client.key, \
     or --client-key FILE). It keeps the operator's part under NAME (operator-NAME.json, see FILES). podssh \
     operator NAME, podssh ssh node://NAME and podssh relay status NAME find it there, as they find a pair. stdout \
     has one line, the label, the node's label and fingerprint and the expiry. A code that nobody holds (it \
     expired, it was used, or it was typed wrong at its number) and a wrong code are 77; no mailbox reached is 69. \
     The mailboxes: magic-wormhole's public one, wss://relay.magic-wormhole.io/v1, then Least Authority's, \
     wss://mailbox.mw.leastauthority.com/v1, which podssh may use unasked; --pair-mailbox URLS or \
     PODSSH_PAIR_MAILBOX names others, such as podssh relay serve's, and no turns the pairing by code off. Both \
     ends name the same ones. Where no mailbox answers, the ends meet at the next place, in this order: a public \
     ntfy server's topic of the code (PODSSH_PAIR_NTFY), then a public Nostr relay's ephemeral events \
     (PODSSH_PAIR_NOSTR). Then a public WebTorrent tracker's peers (PODSSH_PAIR_TRACKER), then a public MQTT \
     broker's topic (PODSSH_MQTT); a line names each third party before its first byte, and the pairing's proof \
     keeps the messages secret from it.",
    "podssh relay spec reads the relay's /health and its published document, /llms-full.txt. It checks the \
     document against the facts that podssh was built with (see RELAY FACTS). It prints ok, with the document's \
     lines, its digest and the version that the relay serves. Else it prints a FAIL line for each fact that \
     disagrees, and exits 1: the relay changed something that podssh depends on. With --document FILE, it checks \
     FILE and reads nothing from the network.",
    "podssh relay conform --relay-host HOST[:PORT] checks whether one relay host keeps the contract, by using it. \
     It never checks the default relay unless you name it, as it mints tokens there. Each check is one line: pass, \
     fail or skip, its id, the section of the contract, its time and its words. With --json, one object holds \
     checks, each with id, clause, verdict, detail and ms, and passed, failed, skipped and exit. The forward \
     checks: /health and /relays.json, a minted token and its form, and an upgrade with no token or a wrong one, \
     each refused with 403. Then ?dial=lazy, a Ping and its Pong, the Close of a session that dialed nothing \
     (1000), and the refusal of a link-local target. A token of one session, where the relay mints one, checks \
     that a token in the query string is refused; then an upgrade spends it. With --target HOST:PORT, best an \
     echo server of yours: bytes each way, the Close after them, the keepalive, and the idle cut that \
     /relays.json publishes, up to 300 s. With --reverse: a pair of the check's own, its node's hello, an \
     operator's leg opened and readied, a byte each way and the leg's close. Then the status, a wrong stop token \
     refused, the renewal and the halt where the relay offers them, and the pair's stop. The stop comes also \
     after a failure; the pair's tokens must be refused after it. No token is printed. The exit is 0 with no \
     fail, 1 with one, and 69 when the host did not answer.",
    "podssh relay status with no NAME asks each relay host for its /health, one after the other. It prints a line \
     for each as it answers: the relay's version, the edge that answered, the time, the TLS version and how the \
     connection was made, or why it failed. It needs one host that answers.",
    "podssh relay info reads /relays.json from the first relay host: the edge that this host reaches, and the pool \
     in the relay's order with its rank and its estimate of each round trip. It reads the limits of a session too. \
     The relay makes that order from the edge that served the request, so two calls can disagree, and neither \
     measures this host's path: podssh relay rank measures each host of the pool, and podssh relay status times \
     the hosts that podssh tries. podssh ping --relay-host HOST times one. Each measures from this host. A relay \
     that names no edge and scores no host above 0, as podssh relay serve, is said to give no estimate. The next \
     line says which order a run from this host takes, with the list in that order, read from the cache with no \
     connection. It uses the words of podssh doctor's line rank: the rank kept for this egress, the times of \
     earlier races, the relay's order, RelayRank no, or the order that you named. With --json, the relay's fields \
     are unchanged, and pool_order says whose order the pool is in and from which edge. relay_order gives the \
     order of a run in podssh status's word (rank, samples, pool or off), or named for a list that you named. \
     relay_list gives its hosts (host, port), in that order. With HOST PORT, also the URL that the relay chooses \
     for that target.",
    "podssh relay rank measures each relay host from this host, one at a time, and keeps the rank: the \
     default host and each host of its pool (the pool read first when none is cached), or the hosts of \
     --relay-host. Each round probes each host in a new random order, 250 ms apart. A probe is a session to \
     github.com:22 (--target HOST:PORT for another) that sends no byte. It times the dial, TLS and the upgrade, \
     the token's time left out, then --count pings; --rounds rounds, 3 by default, within 10 minutes. The hosts go \
     in the order of the share of probes that failed, then the median time to open, then its p95; two medians \
     within 50 ms or 10 % keep the order that the hosts came in. A line for each probe goes to stderr, and the \
     rank to stdout, best first, or as one object with --json. The rank is a private file of the cache, \
     relay-rank.json, with no token and no name of the proxy: the egress is a digest of the proxy's host and port, \
     or direct, and the rank holds 24 h for it. --cached prints the rank kept, its age and whether it holds here, \
     and --forget removes it; neither connects. Exit 0 when a host opened, 69 when none did or PODSSH_OFFLINE is \
     set, 64 for a bad flag. podssh probes no host that the user did not ask it to, unless RelayRank auto asks \
     (below).",
    "The default list of relay hosts takes the rank: while a rank of podssh relay rank holds for this egress, the \
     default list takes it. The list is then the default host and the best three other hosts of the pool, in the \
     rank's order. A run tries the default host at its place among them; the record of failures still moves a host \
     that failed lately to the end. Each run also keeps the time to open of each host that opened in its race, the \
     last 8 of each. It makes no connection of its own for them; where no rank holds, those times order the pool. \
     A list that the user names (--relay-host, PODSSH_RELAY, RelayHost) keeps its order. PODSSH_RELAY_RANK=no, or \
     RelayRank no in the settings file, gives the relay's order of the pool, as before; podssh status says which \
     order a run takes (relay_order), and podssh doctor's line rank and podssh relay info name it with the list.",
    "A rank in a session's background comes only when the user asks for it, never by default. RelayRank auto in \
     the settings file asks, or PODSSH_RELAY_RANK=auto. Then, when no rank holds for this egress, a session of \
     podssh ssh that the default list carries makes one. It probes the default host and the hosts of its pool, 8 \
     at most in a day, in its own process, one at a time: the first after the session ran 60 s, then one each 10 s \
     at most. None runs while a race of relay hosts runs, and none with PODSSH_OFFLINE. None runs past the \
     session's end, which drops a probe in flight. Each probe is a session to github.com:22 with ?dial=lazy that \
     sends no byte and three pings. So the relay dials no target, and the time to open is this host's leg alone. \
     The rank is kept after each probe, source background, and the default list takes it as it takes one of podssh \
     relay rank; a session that ended first leaves it partial, and the next session of the day goes on with the \
     hosts that it lacks. A rank that holds, of either source, makes no new one for 24 h. podssh proxy, pipe, cp \
     and the other commands make none. podssh status gives relay_rank_auto (asked, by, last_ms, last_age_s, \
     partial), and podssh doctor's line rank names the setting and when the last background rank was made.",
    "podssh relay trace HOST PORT asks the first relay host to dial the target and to read its first line. It \
     sends a forward token in a header, never in the URL. It shows: the relay's verdict (live, or \
     silent-or-unreachable for a target that sent nothing) and the address that it dialed. It also shows the times \
     of the connection and of the first byte, and the banner. A target that the relay will not dial (a blocked \
     range, a name with no address) gives the relay's reason. It tells a target that is down from a relay that \
     cannot be reached. The relay's view of this host's address and place, which it sends too, is never shown.",
    "With --json, status, info and trace write one JSON object on stdout when the run ends: schema (1), \
     podssh, and the answer: each host for status with no NAME, and the pair's state for status NAME or \
     --pair-file. For info it is the relay's /relays.json as it came, and for trace the relay's view of the \
     target. The exit codes are in EXIT STATUS.",
    "podssh relay serve is the relay itself, as a role of podssh: it serves the relay's forward road, the contract \
     that podssh speaks (version 2026-10-03-r2), on --listen ADDR:PORT. Its TLS is from --cert FILE and --key FILE \
     (a P-256 key in PEM), or from --acme NAME. So each podssh reaches it with --relay-host and the CA that signed \
     its certificate. It serves /health, /v1/mint, /connect/HOST/PORT, /relays.json, /trace and /llms-full.txt, \
     dials a target only once its name resolves to public addresses (--allow-private dials the others too; \
     --routes RANGES, those inside its ranges alone, ADDR/BITS or one address, separated by commas, each address \
     of a name checked, and never beside --allow-private; a prefix that sets bits past it, as 10.0.0.5/8, is \
     refused with the network that it names). It refuses port 25 in each case. It answers a name that does not \
     resolve, or not to a public address, with one 403 that names no address. The cause is a line on stdout. It \
     keeps the default relay's limits unless told: 180 s with no payload (--idle SECONDS, 1 to 86400) and 12 hours \
     (--session-hours H, 1 to 168). Also 64 MiB a session (--max-session-mib M, 1 to 4096) and 10 s to dial a \
     target (--connect SECONDS, 1 to 120). Also an empty frame each 25 s (--keepalive SECONDS, 1 to 3600). \
     /relays.json publishes the first four as they are, never the keepalive. A value above the default moves this \
     role's cut only: a client keeps its own lower budgets and its own warning, as it only lowers them to what \
     /relays.json says. --mint anyone mints a token for each client; by default it mints for no one (503), as its \
     tokens are given another way. A token lives until the relay stops. Each mint, upgrade and refusal is a \
     line on stdout, and so is each session's end: end client, end gone, or end close CODE REASON. It \
     listens because you ask it to, and PODSSH_LISTEN=no refuses it; Ctrl-C or SIGTERM stops \
     it.",
    "--cover DIR answers the role's own TLS name as a static site from DIR while the tunnel keeps the same \
     name: index.html for /, each asset with its type, robots.txt, the site's own 404.html, and a Server header \
     of --cover-server VALUE (default nginx). A request that is no route of the contract, an unknown Host and a \
     path that leaves DIR get the site's own 404; a body and a header of an unauthenticated path never name \
     this project, its version or its contract. The documents leave the public listener under --cover: /health, \
     /trace, /llms-full.txt, /relays.json and /v1/probe/* answer the site's 404 there. --control-socket PATH \
     (required with --cover, mode 0600) serves them on a Unix socket of the owner's instead. A PATH longer than a \
     socket's address holds (103 bytes on macOS, 107 on Linux) is bound at PATH through a short link to its \
     directory under /tmp, and the first line says that a client needs a shorter way to it; one that no link \
     serves is refused (78). /v1/mint stays \
     public, and a POST with a body alone: another method is 405 with Allow: POST, an empty body 400. A client \
     that authenticated with a token at POST /v1/delegate gets a temporary credential of the same name and \
     chain. It is bound to the TLS exporter of the connection. podssh-ws checks its issuer, name, window and \
     binding, and refuses another issuer, a lapsed window or another chain by name. \
     This is an application-layer credential, not RFC 9345 and not a TLS delegated credential: no \
     CertificateVerify, no certificate extension, and the TLS stack still authenticates the certificate. One \
     name for each deployment: a certificate whose leaf names a wildcard, or not the name that --acme asked for, is \
     refused (78) in both modes. A leaf of more than one name is a warning. Under --cover each name that the role \
     terminates must be given by --cover-name (repeatable, the first is the role's name). A --cover-name that the \
     certificate does not hold is refused (78), and one that is also a --publish name is refused (64). \
     --cover-name without --cover, and --cover-script without --cover, are refused (64). --cover-script FILE loads \
     a TOML measurement and refuses a missing script or one with no date (78); it is checked at the start, and the \
     tunnel's records are not shaped by it yet, which the record layer's own work covers. A --control-socket or \
     --cover-server without --cover is refused. A published name whose node is gone still closes before any TLS of \
     the role answers.",
    "On Linux the relay gives up each capability that it started with, once its listener is bound and before it \
     serves. A port below 1024 needs one for its bind alone (a start as root, or the file capability \
     cap_net_bind_service on the binary). It gives up: no new privileges on an exec, the bounding set where the \
     capability to change it is held, and the effective, permitted and inheritable sets. It gives them up on each \
     of its threads, which are then read again. Its first line on stderr says so; a start that held none says \
     nothing. A step that fails, or a thread that keeps a capability, stops the start (78). The uid stays: a start \
     as root stays uid 0, which may still write each file that root owns, and its first line says so; a user of \
     its own with the file capability binds the port with none of root's. The role reads some files again: its \
     certificate on SIGHUP, the file of --pairs, the cache of ACME. Such a file of another owner must then let it \
     read by its mode. Other systems have no such sets, and nothing is dropped there.",
    "Where HTTPS_PROXY (or https_proxy, all_proxy, ALL_PROXY) is set, the relay dials each target through that \
     proxy. It does so as each client of podssh reaches its relay, by HTTP CONNECT or SOCKS5; the loopback, and \
     what NO_PROXY names, go directly. Its policy checks each address of a name as it resolves on this host. The \
     proxy is asked for each checked address, never for the name. So a proxy that resolves the name otherwise \
     reaches nothing unchecked; with --allow-private, which checks nothing, the name goes to the proxy as it came. \
     So a host with no DNS reaches each target that its proxy reaches. A proxy's refusal is the relay's 502, with \
     the proxy's status, in words that never say where the proxy is; the relay's own line on stdout names it, and \
     never its credentials. /trace names the road proxy and its kind. The first line on stderr names the proxy by \
     its host and port, and a proxy that cannot be read stops the start (78).",
    "The relay dials an IPv6 target where its host routes IPv6 out. It learns this from the table of routes that \
     Linux gives as a file (/proc/net/ipv6_route). Else it learns it from a dial that met no route in the last \
     minute. Where it does not route IPv6 out, the target gets 502 before the upgrade, also with ?dial=lazy: this \
     relay's host has no IPv6 route out, and a client tries its next relay host. A name of both families keeps its \
     IPv4 addresses; the loopback is the relay's own; through HTTPS_PROXY the proxy decides. /relays.json says \
     what the relay knows, as egress.ipv6: true, false, or null.",
    "Beside the contract it serves /v1/layer/HOST/PORT, the forward road in the resumable layer, for a \
     target that speaks no layer, a standard sshd among them: each WebSocket is one link. Where a way \
     refuses the upgrade, a session of its HTTP road carries a link instead, with the same checks: \
     /v1/http/open-layer/HOST/PORT or /v1/http/one-layer/HOST/PORT. The relay dials the \
     target once, after the layer's handshake of a new session. It keeps the target while the client's link is \
     lost, until a resume on a new link to this relay carries the session on. Else 10 minutes pass and the target \
     is shut. The token, the upgrade and the policy are checked as on /connect/, with the same refusals; the \
     layer's secret never crosses the relay, as each resume proves it, and the path names the target alone. Each \
     link keeps the limits of a session, and the client moves the session to a new link before them. The sessions \
     hold 256 MiB of replay buffers at most, 4 MiB each (--resume-budget MIB; 0 serves none), and one whose link \
     is lost is kept 10 minutes (--resume-deadline TIME). A new session past the budget is refused in the layer's \
     handshake, before its client sent a byte of it. The refusal says what holds the budget, and a line on stdout \
     says so once a minute; podssh's client then takes /connect/, with no resume. /relays.json offers it as \
     forward.layer: true, and podssh proxy and podssh ssh take it, with PODSSH_RELAY_LAYER unset or yes. Where \
     several processes serve one name, each gives --resume-host HOST[:PORT], a name of its own that its \
     certificate holds: /relays.json names it as forward.host. podssh's client sends each link of a session there, \
     so that a resume reaches the process that holds the session; a name that is not of the deployment of the host \
     that the client asked is not taken. A restart forgets each session.",
    "It serves the reverse road too: /v1/pair, for whom it mints, /v1/node/NAME, /v1/connect/NAME, /v1/status/NAME \
     and /v1/stop/NAME. So podssh relay pair --relay-host, podssh node and podssh ssh node:// work through it with \
     no other relay. A pair lives 72 hours. /v1/renew/NAME, with the stop token, gives it 72 hours from then with \
     its tokens, as often as its owner asks. podssh relay pair --renew asks so, and its node does in its last day; \
     /v1/status/NAME names the expiry beside the contract's fields. /v1/halt/NAME, with the stop token, keeps a \
     pair's operators out while its node keeps its socket (podssh relay halt). /v1/resume/NAME, with the stop \
     token, lets them in again (podssh relay resume); the status says halted. --pairs FILE keeps the pairs in \
     FILE, so that they outlive a restart. FILE is of mode 0600, and holds the digests of their tokens and never a \
     token. At most 1 MiB waits for a slow operator: past it, the session ends with 1011 relay backpressure, and \
     the node's other sessions go on; a node that reads slowly slows its operators instead, each session's frames \
     to it a turn each. So one operator's upload never holds another's keystrokes behind it. A frame of the node \
     for a session that ended in the last 2 seconds was on its way, and is dropped; one for an id never given \
     closes the node's socket with 1003, as the contract says. Ctrl-C or SIGTERM first closes each socket of the \
     reverse road with 1012. So each node connects again, and each session resumes once the relay is back with its \
     pairs: each socket gets the frames that wait for it first, 1 second at most. The role waits for each answer \
     to its Close, 3 seconds at most in all; a node or an operator that comes meanwhile gets 503 and tries again. \
     Where nothing may listen, the node of a quick tunnel serves the same roads behind its tunnel, with no \
     listener. The tunnel's name is then the relay host: see podssh node --relay.",
    "--mint keys:FILE mints tokens and makes pairs for the keys of FILE alone. FILE is a list in the format of \
     podssh node --allow, read again for each request. A request with no key gets 401 and a challenge of the \
     relay's, which lives a minute; podssh then asks once more with the key of this client (client.key in the \
     cache, the key that a node's list lets in). It sends the challenge and the key's signature of them, of the \
     relay's name and of the path. Each of these gets 403: a key that is not on the list, a signature that does \
     not verify, a challenge that ended or was answered before. So does a request whose Host is not the name that \
     its TLS asked for. The 403 names the key's fingerprint for the owner's list. podssh caches the token as any \
     other.",
    "FILE of --mint keys:FILE may be an https:// URL, for a relay whose image has no writable volume: the list is \
    fetched through the host's proxy with the trust of --ca-file, 1 MiB at most. A fetch has 20 seconds and three \
    redirects at most, to https:// alone. It is fetched once before the relay takes a connection, which stops the \
    start (78) when it fails. Then it is fetched again each --list-ttl SECONDS (300). A fetch that fails leaves \
    the copy to age, and a line on stderr says so; a copy older than its TTL and --list-stale SECONDS (3600) lets \
    no key mint until a fetch works. A file that cannot be read does the same. An answer of the server is the \
    list, whatever it holds: a page that is no list lets no key mint. A key taken off the list mints until the \
    next fetch, not the next request, as a file's would. Its trust is TLS alone; --mint net, whose document its \
    owner signs, is the stronger way. Each line names the URL by its host alone, as its path may hold a secret; an \
    http:// URL is refused (64), and another FILE is a file, as before. The relay behind a node's quick tunnel \
    takes the same words, at the defaults.",
    "--mint net mints tokens and makes pairs for the members of the net that this host holds (see podssh net). \
     Each member proves itself by the same signature, with the key that the net names for it; --mint net,keys:FILE \
     for those and the keys of FILE. The document is read again, and its owner's signature checked, for each \
     request: a member that a newer document removed is refused from that serial on. A token that it minted before \
     lives until its end or the relay's stop, as a token of a list's key does. Where the net has a policy, a \
     member mints only where a rule lets it reach relay:*. The rule names the relay so, as podssh relay serve is \
     no member of the net; the relay behind a node's quick tunnel is reached by relay:NAME too, NAME the node's \
     name in the net; with no policy each member mints. A host that holds no net, or one that ended, does not \
     start (78). The 403 of a key that is no member names the key and the document's serial, never the net or its \
     members. A member's refusal by the policy names them.",
    "With --mint keys:FILE or net, half of the relay's 4096 pairs is a reserve. It is in equal parts for the keys \
     that it mints for at that moment. The other half goes to whoever asks first: a key makes a pair within its \
     reserve, or past it while the places left still hold each other key's. Else it gets 429 with its own count \
     and share (this key holds N pairs, past its share of M while others wait). The 429 names no other key. A pair \
     keeps the fingerprint of its key, also in --pairs FILE, so that the share holds across a restart; a pair that \
     is stopped or expires gives its place back.",
    "With --mint keys:FILE or net, the relay counts what each key carried. A token names no key and ends at a \
     restart. So at each mint for a key, the relay keeps the token's SHA-256 with the key's fingerprint. It keeps \
     them in memory until the token ends, 64 live tokens a key at most. The forward road's sessions are /connect/, \
     each link of /v1/layer/ and a session of the HTTP road. Each counts its payload each way and charges its key \
     once, at its end; an empty keepalive frame is no byte, and a refusal is no session. --quota MIB is each key's \
     budget for a day (UTC), both ways together: once a key spent it, a session gets 403 forward: this key's quota \
     of MIB for today is spent. The 403 comes before its target is dialed, until the next day. A line on stdout \
     says the session that spent it. A session that began under the budget runs to its own end. So a key may pass \
     its budget by the sessions that it holds open. Under a budget, a token that the relay holds no more, past a \
     key's 64, gets 403, and podssh mints another. --usage FILE keeps each key's totals of the day and the day \
     before in FILE, of mode 0600, so that they outlive a restart. FILE is written through a file beside it and a \
     rename each 2 s while a count moved, and at a planned stop; a file that does not read stops the start (78), \
     and a write that fails is a line. SIGHUP says each key's totals on stderr, the most of today first. Both \
     flags with --mint anyone or nobody, which count no key, are refused (64).",
    "The certificate and its key are read again on SIGHUP, and when either file changes, which the \
     role looks at each minute; on Windows, which has no SIGHUP, that is the way. The handshakes after \
     the read take the new pair, and each session that is open goes on with its own. A pair that does not load, or \
     whose key is not the key of its first certificate, is said on stderr. The pair of before then stays. The role \
     takes SIGHUP for this, so SIGHUP no longer stops it.",
    "--acme NAME takes a certificate for NAME from an ACME CA (RFC 8555): Let's Encrypt, unless \
     --acme-directory URL names another, such as a CA's staging directory or Pebble for a test, whose \
     own certificate --ca-file names. The CA validates NAME by TLS-ALPN-01 (RFC 8737) on the role's \
     own listener, so nothing else listens: NAME must resolve to this host, and the CA's connection to \
     its port 443 must reach --listen. A new account agrees to the CA's terms, which the role names as \
     it makes the account. The account's key, and the certificate with its own P-256 key in one file, are kept in \
     the cache (acme/, see FILES). Each is of mode 0600, in a directory of mode 0700. So a restart serves the \
     certificate kept and asks the CA for nothing; PODSSH_CACHE_DIR=none refuses --acme (78), and so does a cache \
     with no directory that can be made private (73). The role renews the certificate 30 days before its end, or \
     at a third of its life left for a shorter one. The renewal has a new key, and the next handshakes take it. A \
     renewal that fails is said on stderr, and the certificate of before stays. It is asked again after 5 minutes, \
     then twice as long each time up to 6 hours. When no certificate is kept and the first order fails, the role \
     stops with the CA's reason (69). SIGHUP reads the file kept again.",
    "podssh relay serve is a mailbox of the pairing by code too, at /v1/mailbox: magic-wormhole's mailbox protocol \
     for podssh's application alone. So the two ends of podssh relay pair --code and podssh relay join meet at \
     your own relay with --pair-mailbox wss://HOST/v1/mailbox. A client of magic-wormhole's own library with \
     podssh's application id meets them there. It keeps its nameplates and mailboxes in memory, two sides each (a \
     third gets crowded). A mailbox holds 32 messages of 8 KiB at most each. Each is kept for 20 minutes at most; \
     it learns no code. Each connection to it is braked as a request of /v1/pair is.",
    "The relay brakes /v1/mint and /v1/pair for each address, as the default relay does: 120 requests of one \
     address within a minute, the two together, and then 429 with Retry-After. Retry-After is the seconds until \
     the oldest of them is a minute old, which podssh says. The address is the connection's own, never a header \
     that a client sends; an IPv6 address counts by its first 64 bits. The relay counts 4096 addresses at most, \
     and forgets the one heard from least lately first. /health, the documents and the sockets of both roads are \
     not braked, and the first refusal of an address is a line on stdout.",
    "The relay's listener takes the cleartext road beside TLS, for a client whose proxy tunnels CONNECT \
     but cuts TLS that it does not know: a connection whose first byte begins no TLS handshake is served with no \
     TLS. It is served only with what a session needs with a token of one session, as each hop reads it: GET \
     /health; POST /v1/mint?once=1, for whom --mint names and under the same brake, which answers a token that \
     lives 5 minutes, with \"once\": true; and /connect/HOST/PORT with that token in X-Relay-Token, which its \
     upgrade spends, whatever its end, so that a second use is refused. A token of 72 h, the mint of one, the \
     reverse road, the documents and the probes are refused there (403), and go over TLS. --cleartext no serves \
     TLS alone. Over TLS, POST /v1/mint?once=1 mints the same token of one session.",
    "--sshd ADDR:PORT shares the relay's port with an sshd of yours, for a host that lets one port in: a \
     connection of the listener whose first four bytes are SSH-, the start of an SSH client's version line, goes \
     to the sshd at ADDR:PORT. The sshd reads each of its bytes as they came, and each byte of the sshd goes back; \
     a record of TLS goes to TLS, and another start to the cleartext road, as before. So the port publishes a \
     shell to each client that reaches it, behind that sshd's own authentication alone: no token, no brake and no \
     limit of the relay stand before it. The sshd sees each client as the address that the relay dials it from. \
     OpenSSH 9.8 and later shut out a source of failed logins (PerSourcePenalties). So they would shut out each \
     client of the port for one client's failures: give that sshd PerSourcePenaltyExemptList with that address. \
     Each connection is a line on stdout, and another at its end. The line names the client's address and the \
     relay's own end of its connection to the sshd. The sshd's log names that end in the client's place. A client \
     that waits for the server's line before it sends its own reaches no sshd, as the relay never speaks for one; \
     OpenSSH's client sends its line first. The sshd is no target of the relay's policy: it is dialed as you named \
     it, the loopback and what NO_PROXY names directly, another address through HTTPS_PROXY where it is set. Where \
     the sshd does not answer, the client gets one line that says so, before any version line. The relay's line on \
     stdout names the sshd and why. ADDR is an address, not a name (64). The first line says that SSH goes to that \
     sshd.",
    // A name published to a pair's node by its ClientHello (T-649).
    super::notes_publish::RELAY,
    // DERP for the node keys of a file (T-106).
    "--derp-keys FILE serves DERP at /derp, over a WebSocket of the subprotocol derp, as Tailscale's \
     derper serves it to the keys that it verifies: a node of podssh ts in its relay mode takes it in the place of \
     the operator's Tailscale relay. The flag of podssh ts that names a DERP server pins the node to this relay. \
     Two nodes whose keys FILE lists meet here. FILE holds one node key a line, nodekey:HEX (# starts a comment); \
     it is read at the start, where a line that is no key stops it (64). It is read again at each login, so that a \
     key added takes no restart. A key that it does not list is closed with 1008 not authorized, which podssh ts \
     reads as the refusal of its node key (77). Each packet goes to the key that it names, 32 of them waiting for \
     a receiver at most; /derp/probe and /derp/latency-check answer an empty 200. The packets are WireGuard's, \
     sealed end to end: the relay sees keys, sizes and times. Each login and each end is a line on stdout, with \
     the key's first 8 hex digits.",
    // iroh's relay protocol and DERP as a net's meeting point (T-720).
    "--relay-roads WORDS makes the relay the meeting point of a net, on its one listener. A net whose hosts \
     let only port 443 in then needs neither n0's iroh relays nor Tailscale's DERP fleet. WORDS is iroh, derp, \
     or both, separated by a comma. iroh serves iroh's relay protocol at /relay, with iroh-relay's own server \
     code. An iroh endpoint whose relay URL is https://HOST:PORT/ meets other endpoints here. It admits the \
     endpoints whose keys --mint admits: anyone, the keys of its list, or the members of its net. With --mint \
     nobody it admits none, so the start stops (64). A refused endpoint gets iroh's denial, not authorized. \
     /ping answers an empty 200, as iroh's relays answer. derp serves DERP at /derp, as --derp-keys does. With \
     no --derp-keys, it admits each node key, and only with --mint anyone (64 otherwise). Each road serves \
     /generate_204, the probe of a captive portal, with the answer to an iroh or Tailscale challenge. \
     /relays.json names each road as meet, null where it is off. Each endpoint that comes and goes is a line \
     on stdout. The datagrams are sealed end to end: the relay sees keys, sizes and times. A build with no iroh \
     road refuses iroh (70).",
    "The relay's TLS offers h2 before http/1.1 (RFC 8441): a client that chooses it gets SETTINGS that offer \
     extended CONNECT and 16 streams at once. Each stream has a window of 1 MiB in one of 16 MiB for the \
     connection. So the sessions of a client's process are streams of one connection. A CONNECT whose :protocol is \
     websocket is the upgrade of its path, with its token and its checks. It is answered 200 where the upgrade is \
     answered 101; GET /health, /relays.json, /trace and /llms-full.txt, and POST /v1/mint, answer there too; \
     another request, such as the HTTP road's, a probe's or a pair's, is asked for again over HTTP/1.1. The answer \
     is HTTP_1_1_REQUIRED, which a client of HTTP/2 follows at once. A connection with no stream for 2 minutes \
     ends. --http2 no offers http/1.1 alone, as before; the first line says which.",
    "--quic yes serves QUIC too, on UDP at the address and port of --listen. The role binds that port with its \
     listener, before it gives up its capabilities; PODSSH_LISTEN=no refuses it with the listener, and a port of \
     UDP that another process holds stops the start (69). Its TLS is 1.3, with the certificate that the listener \
     presents at that moment. It offers the ALPN podssh-relay/1 alone, so that no client of HTTP/3 and no CA's \
     validation gets a connection there. Each bidirectional stream that a client opens is one connection of \
     HTTP/1.1 to the same routes, with the same tokens, checks, brake and limits; a connection holds 64 streams at \
     most, and ends after 30 s with no packet. Each connection is a line quic on stdout. /relays.json offers it as \
     forward.quic, the port. podssh's client keeps it with the offer of the resumable layer, and races it before \
     its TCP roads (see THE RELAY). The first line says QUIC on UDP and its address.",
    super::notes_grant::RELAY,
    super::notes_legs::RELAY,
    // The sessions readied ahead for a node that asks (T-650).
    super::notes_spares::RELAY,
    // The dialect of the reverse road (T-643).
    super::notes_dialect::RELAY,
    super::notes_doctor::RELAY_PROBES,
    super::notes_deployments::RELAY,
    super::notes_deployments::MEMBERS,
    super::notes_deployments::LEGS,
];
