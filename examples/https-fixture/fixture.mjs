import { createServer } from 'node:https'
import { setTimeout as delay } from 'node:timers/promises'
import { assertIsolatedNetwork, ISOLATED_PUBLIC_ADDRESS } from '../../dist/index.js'

export const PUBLIC_CANARY = 'ssrf-lab HTTPS allowed fixture'
export const INTERNAL_CANARY = 'ssrf-lab HTTPS internal fixture'
export const PUBLIC_HOST = 'public.ssrf-lab.test'
export const PRIVATE_HOST = 'private.ssrf-lab.test'
export const WRONG_HOST = 'wrong-name.ssrf-lab.test'

/** Real TLS listeners; the injected resolver is deterministic, not a DNS server. */
export async function startHttpsFixture({ key, cert }) {
  // Check before opening listeners or permitting the public-looking address.
  assertIsolatedNetwork()
  let queries = 0
  const internal = await listen('127.0.0.1', key, cert, (_req, res) => {
    res.end(INTERNAL_CANARY)
  })
  let publicSide
  try {
    publicSide = await listen(ISOLATED_PUBLIC_ADDRESS, key, cert, (req, res) => {
      if (req.url === '/redirect/private') {
        res.writeHead(302, { location: `https://${PRIVATE_HOST}/secret` })
        res.end()
      } else {
        res.end(PUBLIC_CANARY)
      }
    })
  } catch (error) {
    await internal.close()
    throw error
  }

  function resolver(publicResolvesPrivate = false) {
    return (hostname, options, callback) => {
      queries += 1
      const done = typeof options === 'function' ? options : callback
      const all = typeof options === 'object' && options?.all === true
      const known = [PUBLIC_HOST, PRIVATE_HOST, WRONG_HOST].includes(hostname)
      if (!known) {
        const error = Object.assign(new Error('No fixture DNS answer'), { code: 'ENOTFOUND' })
        queueMicrotask(() => done(error))
        return
      }
      const address = hostname === PRIVATE_HOST || publicResolvesPrivate
        ? '127.0.0.1' : ISOLATED_PUBLIC_ADDRESS
      queueMicrotask(() => all
        ? done(null, [{ address, family: 4 }]) : done(null, address, 4))
    }
  }

  return {
    origin: `https://${PUBLIC_HOST}`,
    internalOrigin: `https://${PRIVATE_HOST}`,
    wrongHostnameOrigin: `https://${WRONG_HOST}`,
    lookup: resolver(),
    privateAnswer: resolver(true),
    snapshot: () => ({ public: publicSide.counts(), internal: internal.counts(), dnsQueries: queries }),
    async drain() {
      const deadline = Date.now() + 2000
      while (publicSide.active() + internal.active() > 0) {
        if (Date.now() > deadline) throw new Error('Fixture connections did not settle')
        await delay(5)
      }
    },
    async close() {
      await Promise.all([publicSide.close(), internal.close()])
    },
  }
}

async function listen(host, key, cert, handler) {
  const sockets = new Set()
  const count = { tcpConnections: 0, tlsConnections: 0, requests: 0 }
  const server = createServer({ key, cert }, (req, res) => {
    count.requests += 1
    res.setHeader('content-type', 'text/plain')
    res.setHeader('connection', 'close')
    handler(req, res)
  })
  server.on('connection', socket => {
    count.tcpConnections += 1
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })
  server.on('secureConnection', () => { count.tlsConnections += 1 })
  server.on('tlsClientError', (_error, socket) => socket.destroy())
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(443, host, resolve)
    })
  } catch (error) {
    for (const socket of sockets) socket.destroy()
    throw error
  }
  return {
    counts: () => ({ ...count }),
    active: () => sockets.size,
    async close() {
      for (const socket of sockets) socket.destroy()
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
    },
  }
}
