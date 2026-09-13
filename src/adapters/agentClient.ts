import { type Agent, request as httpRequest, type IncomingMessage } from 'node:http'
import { assertAllowedProtocol, readCapped, redact } from './internal.js'
import { PolicyRefusal, type ClientOptions, type FetchOutcome, type HttpClient } from './types.js'

const MAX_REDIRECTS = 5
const MAX_BYTES = 1024 * 1024
const TIMEOUT_MS = 5000

export interface AgentClientSpec {
  readonly name: string
  /** Builds the library's agent for one URL, the way its README says to. */
  readonly makeAgent: (url: string) => Agent
  /**
   * How the library words its OWN refusal.
   *
   * Without this, a library that refuses correctly is indistinguishable from a
   * socket error, and the scan would credit it with luck instead of a control.
   */
  readonly refusalPattern: RegExp
}

/**
 * Drive a third-party SSRF-protection agent through the range.
 *
 * The agent is rebuilt for EVERY hop, which is what each library's README
 * tells a caller to do. A library is therefore judged on its own terms.
 */
export function agentClient(spec: AgentClientSpec): HttpClient {
  return {
    name: spec.name,
    // These agents judge the address inside themselves and expose no hook a
    // caller can inject, so the rebinding probe cannot drive them.
    supportsConnectHook: false,

    async fetch(url: string, options: ClientOptions = {}): Promise<FetchOutcome> {
      try {
        return await follow(url, options, spec)
      } catch (error) {
        // A library refuses from its agent, from its socket, or by throwing
        // inside createConnection. The 3 routes arrive here differently, so
        // the wording is the only reliable sign that the library decided.
        if (error instanceof Error && spec.refusalPattern.test(error.message)) {
          throw new PolicyRefusal('forbidden-address', error.message)
        }
        throw error
      }
    },
  }
}

async function follow(
  url: string,
  options: ClientOptions,
  spec: AgentClientSpec,
): Promise<FetchOutcome> {
  const deadline = AbortSignal.timeout(options.timeoutMs ?? TIMEOUT_MS)
  const hops: string[] = []
  let target = new URL(url)

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    assertAllowedProtocol(target)
    hops.push(redact(target))

    const response = await send(target, spec, deadline)
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

function send(url: URL, spec: AgentClientSpec, signal: AbortSignal): Promise<IncomingMessage> {
  return new Promise<IncomingMessage>((resolve, reject) => {
    let request: ReturnType<typeof httpRequest>

    try {
      request = httpRequest(url, { agent: spec.makeAgent(url.toString()), signal }, resolve)
    } catch (error) {
      // ssrf-agent throws synchronously from createConnection.
      reject(error)
      return
    }

    request.on('error', reject)
    request.end()
  })
}
