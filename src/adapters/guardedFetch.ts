import { lookup as systemLookup } from 'node:dns'
import { request as httpRequest, type IncomingMessage } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { classifyAddress, isForbiddenAddress } from '../util/addresses.js'
import { assertAllowedProtocol, guardedLookup, readCapped, redact } from './internal.js'
import { PolicyRefusal, type ClientOptions, type FetchOutcome, type HttpClient } from './types.js'

const DEFAULT_MAX_REDIRECTS = 3
const DEFAULT_MAX_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 3000

/**
 * A client with the 4 controls the range tests.
 *
 * 1. Every hop is judged, not only the first URL.
 * 2. The address is judged where the socket connects, so a second answer
 *    cannot differ from the one that passed the check.
 * 3. The body is capped while it is read, after decompression.
 * 4. ONE deadline covers the whole request, the body read included. A socket
 *    timeout is not a deadline: a target that sends 1 byte per second keeps
 *    the socket busy and holds the connection for as long as it likes.
 */
export const guardedFetch: HttpClient = {
  name: 'guarded client (this repo)',
  supportsConnectHook: true,

  async fetch(url: string, options: ClientOptions = {}): Promise<FetchOutcome> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
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
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
  const lookup = guardedLookup(options.lookup)
  const hops: string[] = []
  let target = new URL(url)

  for (let hop = 0; hop <= DEFAULT_MAX_REDIRECTS; hop += 1) {
    const trusted = target.origin === options.trustedOrigin
    assertAllowedProtocol(target)
    if (!trusted) refuseForbiddenLiteral(target)
    hops.push(redact(target))

    const response = await send(target, trusted ? systemLookup : lookup, deadline)
    const location = response.headers.location

    if (isRedirect(response.statusCode ?? 0) && typeof location === 'string') {
      response.resume()
      target = new URL(location, target)
      continue
    }

    const body = await readCapped(response, maxBytes)
    return {
      status: response.statusCode ?? 0,
      bytesRead: body.bytes,
      bodySample: body.sample,
      hops,
      stoppedByHarness: false,
    }
  }

  throw new PolicyRefusal('too-many-redirects', `more than ${DEFAULT_MAX_REDIRECTS} hops`)
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308
}

/**
 * Refuse an address literal before any resolver runs.
 *
 * `http://2130706433/` carries no name to resolve, and the URL parser has
 * already turned it into 127.0.0.1 by the time this reads the hostname.
 */
function refuseForbiddenLiteral(url: URL): void {
  const host = url.hostname.replace(/^\[|\]$/g, '')
  if (isIP(host) === 0) return
  if (isForbiddenAddress(host)) {
    throw new PolicyRefusal('forbidden-address', `${host} is ${classifyAddress(host)}`)
  }
}

function send(url: URL, lookup: LookupFunction, signal: AbortSignal): Promise<IncomingMessage> {
  const transport = url.protocol === 'https:' ? httpsRequest : httpRequest

  return new Promise<IncomingMessage>((resolve, reject) => {
    const request = transport(
      url,
      {
        lookup,
        signal,
        headers: { 'user-agent': 'ssrf-lab/0.1 (+https://github.com/roshan-amble/ssrf-lab)' },
      },
      resolve,
    )

    request.on('error', reject)
    request.end()
  })
}

/**
 * Turn an abort into the refusal it represents.
 *
 * The deadline is ours, so an abort caused by it is a decision this client
 * made, not a network failure. Reporting it as a failure would hide a control.
 */
function asDeadline(error: unknown, timeoutMs: number, deadline: AbortSignal): unknown {
  if (error instanceof PolicyRefusal) return error

  // The signal is the evidence, not the error code. Destroying a socket that
  // is mid-read surfaces as ECONNRESET, and reading only the code turns this
  // client's own deadline into a network failure.
  if (deadline.aborted) return new PolicyRefusal('deadline', `${timeoutMs} ms elapsed`)

  return error
}
