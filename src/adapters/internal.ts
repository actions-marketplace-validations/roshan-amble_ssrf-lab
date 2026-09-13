import { lookup as systemLookup } from 'node:dns'
import type { IncomingMessage } from 'node:http'
import type { LookupFunction } from 'node:net'
import { createGunzip } from 'node:zlib'
import { classifyAddress, isForbiddenAddress } from '../util/addresses.js'
import { PolicyRefusal } from './types.js'

export const SAMPLE_BYTES = 4096

export interface ReadResult {
  bytes: number
  sample: string
}

/** Protocols a fetcher of untrusted URLs may speak. */
export function assertAllowedProtocol(url: URL): void {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new PolicyRefusal('scheme-not-allowed', url.protocol)
  }
}

/**
 * A URL that is safe to print.
 *
 * A redirect target chosen by the remote host may carry credentials, and a
 * message that quotes it puts them in a log file.
 */
export function redact(url: URL): string {
  const copy = new URL(url.toString())
  if (copy.username !== '' || copy.password !== '') {
    copy.username = '***'
    copy.password = ''
  }
  return copy.toString()
}

/**
 * Resolve a name and judge EVERY address in the answer.
 *
 * A mixed answer is refused whole. One public address beside one loopback
 * address is the attack; connecting to the survivor is what it wants.
 */
export function guardedLookup(base: LookupFunction = systemLookup as LookupFunction): LookupFunction {
  return ((hostname: string, options: unknown, callback: unknown) => {
    const done = (typeof options === 'function' ? options : callback) as (
      error: NodeJS.ErrnoException | PolicyRefusal | null,
      address?: string | { address: string; family: number }[],
      family?: number,
    ) => void

    // Node asks for every address when it selects a family itself. Answering
    // with a single string there fails with ERR_INVALID_IP_ADDRESS, and the
    // guard then looks like a network fault instead of a control.
    const wantsAll =
      typeof options === 'object' &&
      options !== null &&
      (options as { all?: boolean }).all === true

    base(hostname, { all: true }, (error, addresses) => {
      if (error) {
        done(error)
        return
      }

      const list = Array.isArray(addresses) ? addresses : [{ address: String(addresses), family: 4 }]
      const forbidden = list.find((entry) => isForbiddenAddress(entry.address))
      if (forbidden !== undefined) {
        done(
          new PolicyRefusal(
            'forbidden-address',
            `${hostname} resolved to ${forbidden.address} (${classifyAddress(forbidden.address)})`,
          ),
        )
        return
      }

      const first = list[0]
      if (first === undefined) {
        done(new PolicyRefusal('forbidden-address', `${hostname} resolved to nothing`))
        return
      }

      // The socket gets the address this guard judged, and no later answer can
      // replace it. That pinning is what closes the rebinding window.
      if (wantsAll) done(null, list)
      else done(null, first.address, first.family)
    })
  }) as LookupFunction
}

/**
 * Read a body against a byte cap, and count the DECOMPRESSED bytes.
 *
 * The cap is applied while reading. A length check after `await body()` is not
 * a cap, because the bytes are already in memory when it runs.
 */
export async function readCapped(response: IncomingMessage, maxBytes: number): Promise<ReadResult> {
  const gunzip = response.headers['content-encoding'] === 'gzip' ? createGunzip() : null
  const source = gunzip === null ? response : response.pipe(gunzip)

  let bytes = 0
  let sample = Buffer.alloc(0)

  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      bytes += chunk.byteLength
      if (sample.byteLength < SAMPLE_BYTES) {
        sample = Buffer.concat([sample, chunk.subarray(0, SAMPLE_BYTES - sample.byteLength)])
      }
      if (bytes > maxBytes) {
        response.destroy()
        gunzip?.destroy()
        throw new PolicyRefusal('body-too-large', `stopped after ${bytes} bytes, cap is ${maxBytes}`)
      }
    }
  } finally {
    gunzip?.destroy()
  }

  return { bytes, sample: sample.toString('utf8') }
}
