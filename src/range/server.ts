import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import { METADATA_ADDRESS } from '../util/addresses.js'
import { decompressionBomb } from './bomb.js'
import { CANARY_ENDLESS_CHUNK, CANARY_INTERNAL_SECRET } from './canaries.js'

/**
 * A running attack range.
 *
 * It is 2 servers, because 1 is not enough to tell a control from an accident:
 *
 *   public    the site the operator asked for. It stands for the internet, so
 *             a client is allowed to fetch it, and it is where every attack
 *             starts.
 *   internal  the service behind the firewall. Nothing outside may read it,
 *             and it answers with a canary so a hit is provable.
 *
 * Both listen on loopback, because that is the only address this process may
 * bind. The public origin is passed to clients as `trustedOrigin`, which is a
 * LAB AFFORDANCE and never a production setting.
 */
export interface AttackRange {
  readonly origin: string
  readonly port: number
  readonly internalOrigin: string
  readonly internalPort: number
  url(path: string): string
  /**
   * How many requests the internal service has answered.
   *
   * This is the measurement that separates "the control stopped it" from "the
   * client tried and something else failed". A canary in a body proves a hit;
   * this counter proves the ABSENCE of one.
   */
  internalHits(): number
  close(): Promise<void>
}

/** Paths the public server serves. */
export const RANGE_PATHS = {
  index: '/',
  redirectLoopback: '/redirect/loopback',
  redirectDecimalLoopback: '/redirect/decimal-loopback',
  redirectLinkLocal: '/redirect/link-local',
  redirectPrivate: '/redirect/private',
  redirectCredentials: '/redirect/credentials',
  redirectLoop: '/redirect/loop',
  payloadBomb: '/payload/bomb.gz',
  payloadEndless: '/payload/endless',
  payloadSlow: '/payload/slow',
} as const

/** The only path the internal service serves. */
export const INTERNAL_PATH = '/internal/secret'

interface Listener {
  server: Server
  port: number
  sockets: Set<Socket>
}

export async function startAttackRange(): Promise<AttackRange> {
  const timers = new Set<NodeJS.Timeout>()
  let internalHits = 0

  const internal = await listen((_request, response) => {
    internalHits += 1
    text(response, 200, CANARY_INTERNAL_SECRET)
  })

  const publicSide = await listen((request, response) => {
    handle(request, response, `http://127.0.0.1:${internal.port}`, internal.port, timers)
  })

  return {
    origin: `http://127.0.0.1:${publicSide.port}`,
    port: publicSide.port,
    internalOrigin: `http://127.0.0.1:${internal.port}`,
    internalPort: internal.port,
    url: (path: string) => `http://127.0.0.1:${publicSide.port}${path}`,
    internalHits: () => internalHits,
    close: async () => {
      for (const timer of timers) clearInterval(timer)
      timers.clear()
      await close(publicSide)
      await close(internal)
    },
  }
}

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<Listener> {
  const sockets = new Set<Socket>()
  const server = createServer(handler)

  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, port: (server.address() as AddressInfo).port, sockets }
}

async function close(listener: Listener): Promise<void> {
  for (const socket of listener.sockets) socket.destroy()
  listener.sockets.clear()
  await new Promise<void>((resolve, reject) => {
    listener.server.close((error) => (error ? reject(error) : resolve()))
  })
}

function handle(
  request: IncomingMessage,
  response: ServerResponse,
  internalOrigin: string,
  internalPort: number,
  timers: Set<NodeJS.Timeout>,
): void {
  const path = (request.url ?? '/').split('?')[0] ?? '/'

  switch (path) {
    case RANGE_PATHS.index: {
      text(response, 200, Object.values(RANGE_PATHS).join('\n'))
      return
    }

    case RANGE_PATHS.redirectLoopback: {
      redirect(response, `${internalOrigin}${INTERNAL_PATH}`)
      return
    }

    // 2130706433 is 127.0.0.1 written as one decimal number. A refusal that
    // compares the raw host string never sees it; the URL parser does.
    case RANGE_PATHS.redirectDecimalLoopback: {
      redirect(response, `http://2130706433:${internalPort}${INTERNAL_PATH}`)
      return
    }

    case RANGE_PATHS.redirectLinkLocal: {
      redirect(response, `http://${METADATA_ADDRESS}/latest/meta-data/`)
      return
    }

    // 198.51.100.0/24 is TEST-NET-2, reserved for documentation, so this probe
    // reaches no real device on the machine's own network.
    case RANGE_PATHS.redirectPrivate: {
      redirect(response, 'http://198.51.100.1/')
      return
    }

    // Credentials in a redirect target end up in logs and error messages.
    case RANGE_PATHS.redirectCredentials: {
      redirect(response, `http://lab:s3cr3t@127.0.0.1:${internalPort}${INTERNAL_PATH}`)
      return
    }

    // Stays on the public origin, so it tests the hop cap and nothing else.
    case RANGE_PATHS.redirectLoop: {
      redirect(response, RANGE_PATHS.redirectLoop)
      return
    }

    case RANGE_PATHS.payloadBomb: {
      const body = decompressionBomb()
      response.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-encoding': 'gzip',
        'content-length': String(body.byteLength),
      })
      response.end(body)
      return
    }

    case RANGE_PATHS.payloadEndless: {
      endless(response, timers)
      return
    }

    case RANGE_PATHS.payloadSlow: {
      slow(response, timers)
      return
    }

    default: {
      text(response, 404, 'no such target')
      return
    }
  }
}

function text(response: ServerResponse, status: number, body: string): void {
  response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' })
  response.end(body)
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(302, { location, 'content-type': 'text/plain; charset=utf-8' })
  response.end(`follow me to ${location}`)
}

/**
 * A body with no end and no Content-Length.
 *
 * A cap that reads Content-Length and trusts it learns nothing here. Only a
 * running total of received bytes stops this.
 */
function endless(response: ServerResponse, timers: Set<NodeJS.Timeout>): void {
  response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
  const chunk = `${CANARY_ENDLESS_CHUNK}${'A'.repeat(64 * 1024)}`

  const timer = setInterval(() => {
    if (response.writableEnded || response.destroyed) {
      clearInterval(timer)
      timers.delete(timer)
      return
    }
    response.write(chunk)
  }, 10)

  timers.add(timer)
  response.on('close', () => {
    clearInterval(timer)
    timers.delete(timer)
  })
}

/** One byte per second. Only a deadline stops this. */
function slow(response: ServerResponse, timers: Set<NodeJS.Timeout>): void {
  response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })

  const timer = setInterval(() => {
    if (response.writableEnded || response.destroyed) {
      clearInterval(timer)
      timers.delete(timer)
      return
    }
    response.write('.')
  }, 1000)

  timers.add(timer)
  response.on('close', () => {
    clearInterval(timer)
    timers.delete(timer)
  })
}
