import {
  createGuardedDispatcher,
  guardedFetch as upstreamFetch,
  GuardedFetchError,
  readBodyAsText,
} from 'guarded-fetch'
import { redact } from './internal.js'
import { PolicyRefusal, type HttpClient, type RefusalReason } from './types.js'

const REFUSALS: Partial<Record<GuardedFetchError['code'], RefusalReason>> = {
  hostname_unsafe: 'forbidden-address',
  host_not_allowed: 'forbidden-address',
  redirect_to_unsafe_host: 'forbidden-address',
  protocol_not_allowed: 'scheme-not-allowed',
  too_many_redirects: 'too-many-redirects',
  response_too_large: 'body-too-large',
  timeout: 'deadline',
}

/** Use the package's real dispatcher and exported bounded body reader. */
export const vercelGuardedFetch: HttpClient = {
  name: 'guarded-fetch 0.1.5 (guardedFetch + readBodyAsText)',
  // The package has its own guarded lookup, but no injectable base resolver.
  supportsConnectHook: false,
  supportsLoopbackOrigin: false,
  async fetch(url, options = {}) {
    const timeoutMs = options.timeoutMs ?? 5000
    const deadlineAt = Date.now() + timeoutMs
    const dispatcher = createGuardedDispatcher()
    try {
      const response = await upstreamFetch(url, { timeoutMs, dispatcher, opaqueErrors: true })
      let bytesRead = 0
      // Count wire-decoded bytes without supplying a replacement security control.
      const measuredBody = response.body?.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          bytesRead += chunk.byteLength
          controller.enqueue(chunk)
        },
      })) ?? null
      const measured = new Response(measuredBody, { status: response.status, headers: response.headers })
      const body = await readBodyAsText(measured, {
        maxResponseBytes: options.maxBytes ?? 1024 * 1024,
        deadlineAt,
        opaqueErrors: true,
      })
      return {
        status: response.status,
        bytesRead,
        bodySample: body.slice(0, 4096),
        hops: [redact(new URL(url)), ...(response.url && response.url !== url ? [redact(new URL(response.url))] : [])],
        stoppedByHarness: false,
      }
    } catch (error) {
      if (error instanceof GuardedFetchError) {
        const reason = REFUSALS[error.code]
        if (reason !== undefined) throw new PolicyRefusal(reason, `guarded-fetch: ${error.code}`)
      }
      throw error
    } finally {
      await dispatcher.destroy()
    }
  },
}
