import { lookup as systemLookup } from 'node:dns'
import { request as httpRequest, type IncomingMessage } from 'node:http'
import type { LookupFunction } from 'node:net'
import { classifyAddress, isForbiddenAddress } from '../util/addresses.js'
import { assertAllowedProtocol, readCapped, redact } from './internal.js'
import { PolicyRefusal, type ClientOptions, type FetchOutcome, type HttpClient } from './types.js'

const MAX_REDIRECTS = 3
const MAX_BYTES = 1024 * 1024
const TIMEOUT_MS = 3000

/**
 * The common wrong shape: resolve, judge the answer, then connect BY NAME.
 *
 * Every other control here is real. It reads every hop, it classifies
 * addresses correctly, it caps the body and it holds a deadline. It still
 * loses, because the name is resolved a SECOND time when the socket opens,
 * and nothing judges that answer.
 *
 * It exists so the rebinding probe has something to catch. Do not copy it.
 */
export const checkThenConnect: HttpClient = {
  name: 'check-then-connect (naive guard)',
  supportsConnectHook: true,

  async fetch(url: string, options: ClientOptions = {}): Promise<FetchOutcome> {
    const timeoutMs = options.timeoutMs ?? TIMEOUT_MS
    const deadline = AbortSignal.timeout(timeoutMs)

    try {
      return await follow(url, options, deadline)
    } catch (error) {
      throw asDeadline(error, timeoutMs, deadline)
    }
  },
}

async function follow(
  url: string,
  options: ClientOptions,
  deadline: AbortSignal,
): Promise<FetchOutcome> {
  const lookup = (options.lookup ?? systemLookup) as LookupFunction
  const hops: string[] = []
  let target = new URL(url)

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const trusted = target.origin === options.trustedOrigin
    assertAllowedProtocol(target)
    hops.push(redact(target))

    // The check. It is correct, and it is too early.
    if (!trusted) {
      const address = await resolveOnce(lookup, target.hostname)
      if (isForbiddenAddress(address)) {
        throw new PolicyRefusal(
          'forbidden-address',
          `${target.hostname} resolved to ${address} (${classifyAddress(address)})`,
        )
      }
    }

    // The connection. It resolves the name again, and takes what it gets.
    const response = await send(target, lookup, deadline)
    const location = response.headers.location

    if (isRedirect(response.statusCode ?? 0) && typeof location === 'string') {
      response.resume()
      target = new URL(location, target)
      continue
    }

    const body = await readCapped(response, options.maxBytes ?? MAX_BYTES)
    return {
      status: response.statusCode ?? 0,
      bytesRead: body.bytes,
      bodySample: body.sample,
      hops,
      stoppedByHarness: false,
    }
  }

  throw new PolicyRefusal('too-many-redirects', `more than ${MAX_REDIRECTS} hops`)
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308
}

function resolveOnce(lookup: LookupFunction, hostname: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    lookup(hostname, {}, (error, address) => {
      if (error) reject(error)
      else resolve(String(address))
    })
  })
}

function send(url: URL, lookup: LookupFunction, signal: AbortSignal): Promise<IncomingMessage> {
  return new Promise<IncomingMessage>((resolve, reject) => {
    const request = httpRequest(url, { lookup, signal }, resolve)
    request.on('error', reject)
    request.end()
  })
}

function asDeadline(error: unknown, timeoutMs: number, deadline: AbortSignal): unknown {
  if (error instanceof PolicyRefusal) return error
  if (deadline.aborted) return new PolicyRefusal('deadline', `${timeoutMs} ms elapsed`)
  return error
}
