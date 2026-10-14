import { createRequire } from 'node:module'
import { PolicyRefusal } from '../../dist/index.js'

// The published package supplies its compiled CommonJS entry point.
const require = createRequire(import.meta.url)
const {
  OutboundHttp, SsrfProtectionService, DnsResolver, InMemoryDnsCache,
  SsrfBlockedIpError, SsrfBlockedHostnameError,
} = require('@n8n/backend-network')
const { SsrfProtectionConfig, SSRF_DEFAULT_BLOCKED_IP_RANGES } = require('@n8n/config')

const logger = {
  scoped() { return this },
  warn(message) { process.stderr.write(`${message}\n`) },
  debug() {},
}

export function createN8nClient({ api = 'request', enabled = true } = {}) {
  if (api !== 'request' && api !== 'fetch') throw new Error('Unknown n8n API')
  const config = new SsrfProtectionConfig()
  // Make the measured policy independent of the host process environment.
  Object.assign(config, {
    enabled,
    blockedIpRanges: [...SSRF_DEFAULT_BLOCKED_IP_RANGES],
    allowedIpRanges: [], allowedHostnames: [], blockedHostnames: [],
    dnsCacheMaxSize: 1048576,
  })
  const resolver = new DnsResolver(new InMemoryDnsCache(config))
  const policy = new SsrfProtectionService(config, resolver, logger)
  const outbound = new OutboundHttp(policy, config, logger)
  const transport = api === 'fetch' ? outbound.transport({ proxy: false }) : null
  const requestClient = outbound.requests()

  return {
    name: `n8n backend-network 1.17.3 (${api}, protection ${enabled ? 'on' : 'off'})`,
    supportsConnectHook: false,
    supportsLoopbackOrigin: false,
    async fetch(url, options = {}) {
      // This is a harness deadline. It is never credited as an n8n refusal.
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000)
      try {
        let status
        let body
        if (transport) {
          const response = await transport.asCustomFetch()(url, { signal: controller.signal })
          status = response.status
          body = Buffer.from(await response.arrayBuffer())
        } else {
          const response = await requestClient.request({
            method: 'GET', url, returnFullResponse: true,
            encoding: 'arraybuffer', proxy: false, abortSignal: controller.signal,
          })
          status = response.statusCode
          body = Buffer.from(response.body)
        }
        const safeUrl = new URL(url)
        safeUrl.username = ''
        safeUrl.password = ''
        return { status, bytesRead: body.length, bodySample: body.subarray(0, 4096).toString('utf8'), hops: [safeUrl.toString()], stoppedByHarness: false }
      } catch (error) {
        let cause = error
        const seen = new Set()
        while (cause instanceof Error && !seen.has(cause)) {
          seen.add(cause)
          if (cause instanceof SsrfBlockedIpError || cause instanceof SsrfBlockedHostnameError) {
            throw new PolicyRefusal('forbidden-address', `n8n: ${cause.name}`)
          }
          cause = cause.cause
        }
        const message = error instanceof Error ? error.message : String(error)
        // Some URL parsers echo userinfo. Keep it out of evidence files.
        throw new Error(message.replace(/(https?:\/\/)[^/\s@]+@/g, '$1***@'))
      } finally {
        clearTimeout(timer)
      }
    },
    async close() {
      if (transport) await transport.getDispatcher().destroy()
    },
  }
}
