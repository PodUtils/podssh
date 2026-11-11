// A Bare server of TompHTTP's own software (@tomphttp/bare-server-node), for
// the test of the Bare hop (T-740, crates/podssh-ws/tests/bare_hop.rs): it
// serves /bare/ on 127.0.0.1:PORT and prints "ready PORT" when it listens.
// Local addresses are allowed, as the far end of the test is on the
// loopback; REFUSE names a far port that the operator's filterRemote
// refuses, as a node's own rules may.
//
//   node scripts/bare-hop-server.mjs PORT [REFUSE] (NODE_PATH names the
//   node_modules where @tomphttp/bare-server-node is installed)

import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(path.join(process.env.NODE_PATH || process.cwd(), 'x.js'));
const { createBareServer } = require('@tomphttp/bare-server-node');

const port = Number(process.argv[2] || 0);
const refuse = process.argv[3] || '';
const bare = createBareServer('/bare/', {
  blockLocal: false,
  logErrors: true,
  filterRemote: (remote) => {
    if (refuse && remote.port === refuse) {
      throw new Error(`the operator refuses port ${refuse}`);
    }
  },
});
const server = createServer((req, res) => {
  if (bare.shouldRoute(req)) bare.routeRequest(req, res);
  else { res.writeHead(404); res.end('not found'); }
});
server.on('upgrade', (req, socket, head) => {
  if (bare.shouldRoute(req)) bare.routeUpgrade(req, socket, head);
  else socket.end();
});
server.listen(port, '127.0.0.1', () => console.log(`ready ${server.address().port}`));
