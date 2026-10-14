import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { fetch as safeFetch } from '@tak-ps/node-safeurl'
import { environment } from '../../scripts/integration-evidence.mjs'

// Functional HTTP regression, entirely on one explicitly allowed local origin.
// It makes no claim of an SSRF bypass.
const server = createServer(async (request, response) => {
  const chunks = []
  for await (const chunk of request) chunks.push(chunk)
  if (request.url.startsWith('/redirect/')) {
    response.writeHead(Number(request.url.split('/').at(-1)), { location: '/echo' })
    response.end()
  } else {
    response.setHeader('content-type', 'application/json')
    response.end(JSON.stringify({ method: request.method, body: Buffer.concat(chunks).toString(), contentLength: request.headers['content-length'] ?? null, contentType: request.headers['content-type'] ?? null }))
  }
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const origin = `http://127.0.0.1:${server.address().port}`
const results = []
try {
  for (const [status, method] of [[301, 'POST'], [302, 'POST'], [303, 'PUT'], [307, 'POST'], [308, 'POST']]) {
    const measurements = {}
    for (const [name, client] of [['native', fetch], ['node-safeurl', safeFetch]]) {
      try {
        const response = await client(`${origin}/redirect/${status}`, {
          // Let the runtime derive Content-Length; the upstream regression test
          // separately checks caller-supplied framing headers.
          method, body: 'hello', headers: { 'content-type': 'text/plain' },
          signal: AbortSignal.timeout(2000), ...(name === 'node-safeurl' ? { safeUrlAllow: [origin] } : {}),
        })
        measurements[name] = { ok: true, response: await response.json() }
      } catch (error) {
        measurements[name] = { ok: false, message: error.message, cause: error.cause?.code, causeMessage: error.cause?.message }
      }
    }
    results.push({ status, method, ...measurements })
  }
  console.log(JSON.stringify({ environment: environment(), package: '@tak-ps/node-safeurl@1.8.0', scope: 'Same-origin redirect method rewriting, explicit loopback allowlist', results }, null, 2))
  for (const result of results) assert(result.native.ok, `Reference fetch must succeed: ${JSON.stringify(result)}`)
} finally {
  server.closeAllConnections()
  await new Promise(resolve => server.close(resolve))
}
