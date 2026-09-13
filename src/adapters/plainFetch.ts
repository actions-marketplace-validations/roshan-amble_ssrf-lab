import type { ClientOptions, FetchOutcome, HttpClient } from './types.js'

/** How much of the body the harness keeps for canary detection. */
const SAMPLE_BYTES = 4096

/**
 * Node's built-in `fetch`, with its defaults.
 *
 * This is the control case. It follows redirects, resolves names once,
 * enforces no size cap and exposes no connect hook. The harness applies its
 * own deadline so a probe cannot hang the run, and reports when it had to.
 */
export const plainFetch: HttpClient = {
  name: 'node-fetch (global, defaults)',
  supportsConnectHook: false,

  async fetch(url: string, options: ClientOptions = {}): Promise<FetchOutcome> {
    const timeoutMs = options.timeoutMs ?? 6000
    const controller = new AbortController()
    const deadline = setTimeout(() => controller.abort(), timeoutMs)

    try {
      const response = await fetch(url, { redirect: 'follow', signal: controller.signal })
      const { bytesRead, sample, stoppedByHarness } = await drain(response, controller.signal)

      return {
        status: response.status,
        bytesRead,
        bodySample: sample,
        // Built-in fetch follows redirects inside itself, so the hops it took
        // are not observable from here. That opacity is the finding.
        hops: [url],
        stoppedByHarness,
      }
    } finally {
      clearTimeout(deadline)
    }
  },
}

async function drain(
  response: Response,
  signal: AbortSignal,
): Promise<{ bytesRead: number; sample: string; stoppedByHarness: boolean }> {
  if (response.body === null) return { bytesRead: 0, sample: '', stoppedByHarness: false }

  const reader = response.body.getReader()
  const sample: Uint8Array[] = []
  let sampleBytes = 0
  let bytesRead = 0

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytesRead += value.byteLength
      if (sampleBytes < SAMPLE_BYTES) {
        sample.push(value.subarray(0, SAMPLE_BYTES - sampleBytes))
        sampleBytes += Math.min(value.byteLength, SAMPLE_BYTES - sampleBytes)
      }
    }
  } catch (error) {
    if (signal.aborted) {
      return { bytesRead, sample: decode(sample), stoppedByHarness: true }
    }
    throw error
  }

  return { bytesRead, sample: decode(sample), stoppedByHarness: false }
}

function decode(chunks: Uint8Array[]): string {
  return Buffer.concat(chunks).toString('utf8')
}
