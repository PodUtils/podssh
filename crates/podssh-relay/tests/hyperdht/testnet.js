// A private HyperDHT of three bootstrap nodes on the loopback (T-736), with
// the `hyperdht` package of Node.js, software that podssh did not write:
// one line `bootstrap 127.0.0.1:PORT` each, then `ready`; it runs until
// its stdin closes.
const createTestnet = require('hyperdht/testnet')

async function main () {
  const testnet = await createTestnet(3, { host: '127.0.0.1' })
  for (const node of testnet.bootstrap) console.log(`bootstrap ${node.host}:${node.port}`)
  console.log('ready')
  process.stdin.resume()
  process.stdin.on('end', async () => {
    await testnet.destroy()
    process.exit(0)
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
