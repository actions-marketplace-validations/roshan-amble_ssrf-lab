import { PolicyRefusal } from '../../dist/index.js'

const SAMPLE_BYTES = 4096
const MAX_READ_BYTES = 64 * 1024

// This adapter measures a fetch-compatible Response. It does not validate
// destinations, follow redirects itself, or add a security refusal.
export function adaptFetcher(module) {
  if (typeof module.fetchUrl !== 'function') throw new TypeError('Export fetchUrl(url, options) from your module')
  return {
    name: module.name ?? 'custom application fetcher',
    supportsConnectHook: false,
    supportsLoopbackOrigin: false,
    async fetch(url) {
      const controller = new AbortController()
      const timeoutMs = 5000
      let reader
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        let response
        try {
          response = await module.fetchUrl(url, { signal: controller.signal, timeoutMs })
        } catch (error) {
          // The adapter's deadline must never be credited to the client.
          if (controller.signal.aborted) throw new Error('Harness deadline expired')
          const reason = module.classifyRefusal?.(error)
          if (reason === 'forbidden-address') {
            throw new PolicyRefusal(reason, 'the application reported an explicit address-policy refusal')
          }
          throw error
        }
        if (!response || typeof response.status !== 'number' ||
            (response.body != null && typeof response.body.getReader !== 'function')) {
          throw new TypeError('fetchUrl must return a fetch-compatible Response')
        }
        let bytesRead = 0
        let sample = Buffer.alloc(0)
        reader = response.body?.getReader()
        if (reader) {
          // Cancel the response too if a wrapper does not attach our signal to
          // the returned stream. The fetch call itself must honor cancellation
          // or its own finite timeout; do not leave background requests running.
          controller.signal.addEventListener('abort', () => { void reader.cancel().catch(() => {}) }, { once: true })
          while (!controller.signal.aborted) {
            const { done, value } = await reader.read()
            if (done) break
            bytesRead += value.byteLength
            if (sample.length < SAMPLE_BYTES) {
              sample = Buffer.concat([sample, value.subarray(0, SAMPLE_BYTES - sample.length)])
            }
            if (bytesRead > MAX_READ_BYTES) throw new Error('Harness response limit exceeded')
          }
        }
        if (controller.signal.aborted) throw new Error('Harness deadline expired')
        return { status: response.status, bytesRead, bodySample: sample.toString('utf8'), hops: [], stoppedByHarness: false }
      } finally {
        clearTimeout(timer)
        await reader?.cancel().catch(() => {})
        controller.abort()
      }
    },
  }
}

// A stricter onboarding gate than the CLI's --fail-on-reach: unexplained
// prevention is inconclusive, not a passing security assertion.
export function gateScan(scan) {
  if (scan.results.some(row => row.verdict === 'REACHED')) return 1
  if (scan.results.length === 0 || scan.results.some(row =>
    row.verdict !== 'BLOCKED' || !row.note.startsWith('forbidden-address:'))) return 2
  return 0
}
