import { safeFetch as ssrfFetch } from 'ssrf-fetch'
import { safeFetch as ssrfSafeFetch, SsrfError } from 'ssrf-safe-fetch'
import { fetch as nodeSafeUrl } from '@tak-ps/node-safeurl'
import { PolicyRefusal } from '../../dist/index.js'

function causes(error) {
  const list = []
  const seen = new Set()
  while (error instanceof Error && !seen.has(error)) {
    list.push(error)
    seen.add(error)
    error = error.cause
  }
  return list
}

function classify(packageName, error) {
  if (packageName === 'ssrf-safe-fetch' && error instanceof SsrfError) {
    if (/^(Blocked private IP host:|Host .* resolves to private address)/.test(error.message)) return 'forbidden-address'
    if (error.message.startsWith('Blocked non-http(s) URL:')) return 'scheme-not-allowed'
    if (error.message.startsWith('Too many redirects starting from:')) return 'too-many-redirects'
    // This class also covers DNS failures, which are not policy successes.
  }
  if (packageName === 'ssrf-fetch') {
    if (error?.message?.startsWith('safeFetch: blocked host ')) return 'forbidden-address'
    if (error?.message?.startsWith('safeFetch: blocked protocol ')) return 'scheme-not-allowed'
    if (causes(error).some(cause => cause.message === 'unexpected redirect')) return 'redirect-not-allowed'
  }
  if (packageName === '@tak-ps/node-safeurl') {
    if (error?.status === 403 && /^Unsafe (redirect )?URL: /.test(error.message)) return 'forbidden-address'
    if (error?.status === 400 && error.message === 'Too many redirects') return 'too-many-redirects'
    if (error?.status === 400 && error.message === 'Redirects are not allowed') return 'redirect-not-allowed'
  }
  return null
}

export const targets = [
  { package: 'ssrf-safe-fetch', version: '0.1.0', request: ssrfSafeFetch,
    notApplicable: { 'redirect-private': 'Upstream explicitly excludes TEST-NET ranges from its policy.' } },
  { package: 'ssrf-fetch', version: '0.1.0', request: ssrfFetch },
  { package: '@tak-ps/node-safeurl', version: '1.8.0', request: nodeSafeUrl },
]

/** Address probes only: body limits are not promised by these targets. */
export function createClient(target) {
  return {
    name: `${target.package} ${target.version}`,
    supportsConnectHook: false,
    supportsLoopbackOrigin: false,
    async fetch(url, options = {}) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000)
      try {
        const response = await target.request(url, { signal: controller.signal })
        const reader = response.body?.getReader()
        let bytesRead = 0
        const chunks = []
        let sampleBytes = 0
        let stoppedByHarness = false
        if (reader) {
          try {
            for (;;) {
              const { done, value } = await reader.read()
              if (done) break
              bytesRead += value.byteLength
              if (sampleBytes < 4096) {
                const sample = value.subarray(0, 4096 - sampleBytes)
                chunks.push(sample)
                sampleBytes += sample.length
              }
              // Bound harness work; never credit this as a target's own control.
              if (bytesRead > 1024 * 1024) { stoppedByHarness = true; await reader.cancel(); break }
            }
          } catch (error) {
            if (!controller.signal.aborted) throw error
            stoppedByHarness = true
          } finally { reader.releaseLock() }
        }
        const safe = new URL(url)
        safe.username = ''
        safe.password = ''
        return { status: response.status, bytesRead, bodySample: Buffer.concat(chunks).toString('utf8'), hops: [safe.href], stoppedByHarness }
      } catch (error) {
        const reason = classify(target.package, error)
        if (reason) throw new PolicyRefusal(reason, `${target.package}: ${reason}`)
        const detail = causes(error).map(cause => cause.code ?? cause.message).join(' <- ') || String(error)
        throw new Error(detail.replace(/(https?:\/\/)[^/\s@]+@/g, '$1***@'))
      } finally { clearTimeout(timer) }
    },
  }
}
