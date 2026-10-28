import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { isDeepStrictEqual } from 'node:util'
import { fetch as safeFetch } from '@tak-ps/node-safeurl'
import { environment, pinnedVersion } from '../../scripts/integration-evidence.mjs'

// Functional HTTP regression, entirely on one explicitly allowed local origin.
// It makes no claim of an SSRF bypass.
const version = pinnedVersion(new URL('./node_modules/@tak-ps/node-safeurl/package.json', import.meta.url), '1.8.0')
const received = []
const server = createServer(async (request, response) => {
  const chunks = []
  for await (const chunk of request) chunks.push(chunk)
  const observed = {
    method: request.method,
    body: Buffer.concat(chunks).toString(),
    contentLength: request.headers['content-length'] ?? null,
    contentType: request.headers['content-type'] ?? null,
    marker: request.headers['x-fixture-marker'] ?? null,
  }
  received.push(observed)
  if (request.url.startsWith('/redirect/')) {
    const [status, ...remaining] = request.url.split('/').at(-1).split(',').map(Number)
    response.writeHead(status, { location: remaining.length ? `/redirect/${remaining.join(',')}` : '/echo' })
    response.end()
  } else {
    response.setHeader('content-type', 'application/json')
    response.end(JSON.stringify(observed))
  }
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const origin = `http://127.0.0.1:${server.address().port}`
const bodyStep = method => ({ method, body: 'hello', contentLength: '5', contentType: 'text/plain', marker: 'keep-me' })
const getStep = { method: 'GET', body: '', contentLength: null, contentType: null, marker: 'keep-me' }
const cases = [
  ...[301, 302].map(status => ({ statuses: [status], method: 'POST', expected: [bodyStep('POST'), getStep] })),
  { statuses: [303], method: 'PUT', expected: [bodyStep('PUT'), getStep] },
  ...[307, 308].map(status => ({ statuses: [status], method: 'POST', expected: [bodyStep('POST'), bodyStep('POST')] })),
  { statuses: [302, 307], method: 'POST', expected: [bodyStep('POST'), getStep, getStep] },
  { statuses: [307, 302], method: 'POST', expected: [bodyStep('POST'), bodyStep('POST'), getStep] },
  { statuses: [307, 308], method: 'POST', expected: [bodyStep('POST'), bodyStep('POST'), bodyStep('POST')] },
]
const results = []
try {
  for (const { statuses, method, expected } of cases) {
    const measurements = {}
    for (const [name, client] of [['native', fetch], ['node-safeurl', safeFetch]]) {
      const before = received.length
      try {
        const response = await client(`${origin}/redirect/${statuses.join(',')}`, {
          // Let the runtime derive Content-Length; the upstream regression test
          // separately checks caller-supplied framing headers.
          method, body: 'hello', headers: { 'content-type': 'text/plain', 'x-fixture-marker': 'keep-me' },
          signal: AbortSignal.timeout(2000), ...(name === 'node-safeurl' ? { safeUrlAllow: [origin] } : {}),
        })
        const value = await response.json()
        measurements[name] = { ok: true, response: value, requests: received.slice(before) }
      } catch (error) {
        measurements[name] = { ok: false, message: error.message, cause: error.cause?.code, causeMessage: error.cause?.message, requests: received.slice(before) }
      }
    }
    results.push({ status: statuses[0], statuses, method, expected, ...measurements })
  }
  for (const result of results) {
    const label = `${result.method} ${result.statuses.join(' -> ')}`
    assert(result.native.ok, `${label}: reference fetch must succeed`)
    assert(result['node-safeurl'].ok, `${label}: pinned package must complete the control`)
    assert.deepEqual(result.native.requests, result.expected, `${label}: reference observations differ`)
    // Record the known published-package body-header defect without calling it
    // a passing conformance result. Check every actual hop, including controls
    // that preserve the method and body across the whole chain.
    const publishedBaseline = result.expected.map(row => ({ ...row, contentType: 'text/plain' }))
    assert.deepEqual(result['node-safeurl'].requests, publishedBaseline, `${label}: pinned package baseline changed`)
    for (const name of ['native', 'node-safeurl']) {
      assert.deepEqual(result[name].response, result[name].requests.at(-1), `${label}: response must match the destination observation`)
      result[name].matchesReference = isDeepStrictEqual(result[name].requests, result.expected)
    }
    delete result.expected
  }
  console.log(JSON.stringify({
    environment: environment(), package: `@tak-ps/node-safeurl@${version}`,
    scope: 'Same-origin HTTP redirect method/body headers, including chained hops; explicit loopback allowlist. No credentials, TLS or SSRF-policy coverage.',
    cases: results.length,
    nativeMatches: results.filter(row => row.native.matchesReference).length,
    packageMatches: results.filter(row => row['node-safeurl'].matchesReference).length,
    results,
  }, null, 2))
} finally {
  server.closeAllConnections()
  await new Promise(resolve => server.close(resolve))
}
