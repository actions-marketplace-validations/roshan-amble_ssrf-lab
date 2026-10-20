import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { parseArgs } from 'node:util'
import { DIRECT_PROBES, PROBES, plainFetch, runScan, startAttackRange } from '../../dist/index.js'
import { environment, measureClient } from '../../scripts/integration-evidence.mjs'
import { adaptFetcher, gateScan } from '../../examples/custom-fetcher/adapter.mjs'

async function main() {
  const { values } = parseArgs({ options: { 'direct-only': { type: 'boolean', default: false } } })
  const isolated = !values['direct-only']
  // Establish containment before importing the application or opening fixtures.
  const range = await startAttackRange({ publicAddress: isolated })
  let contentServer
  const previousOptOut = process.env.ALLOW_PRIVATE_NETWORK_ACCESS
  try {
    const application = await import('./fetcher.mjs')
    const client = adaptFetcher(application)
    const redirects = PROBES.filter(row => ['redirect-loopback', 'redirect-decimal-loopback'].includes(row.id))
    const probes = [...DIRECT_PROBES, ...(isolated ? redirects : [])]
    const controls = [DIRECT_PROBES[0], ...(isolated ? [redirects[0]] : [])]
    const nativeControl = await measureClient(plainFetch, range, controls, runScan, { positiveControl: isolated })
    assert(nativeControl.results.every(row => row.verdict === 'REACHED' && row.internalHits > 0))
    const scan = await measureClient(client, range, probes, runScan, { positiveControl: isolated })

    let allowedRedirect = null
    if (isolated) {
      let contentHits = 0
      let redirectHits = 0
      const body = '<html><head><title>Linkwarden local content</title></head><body>Fixture</body></html>'
      contentServer = createServer((request, response) => {
        if (request.url === '/redirect') {
          redirectHits++
          response.writeHead(302, { location: '/article' }).end()
        } else {
          contentHits++
          response.writeHead(200, { 'content-type': 'text/html' }).end(body)
        }
      })
      const host = new URL(range.origin).hostname
      await new Promise((resolve, reject) => {
        contentServer.once('error', reject)
        contentServer.listen(0, host, resolve)
      })
      const url = `http://${host}:${contentServer.address().port}`
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 5000)
      try {
        const direct = await application.fetchUrl(`${url}/article`, { signal: controller.signal })
        assert.equal(direct.status, 200)
        assert.equal(await direct.text(), body)
        const redirected = await application.fetchUrl(`${url}/redirect`, { signal: controller.signal })
        assert.equal(redirected.status, 200)
        assert.equal(await redirected.text(), body)
        assert.equal(contentHits, 2)
        assert.equal(redirectHits, 1)
        allowedRedirect = { directStatus: direct.status, redirectedStatus: redirected.status, contentHits, redirectHits, bodyMatches: true }
      } finally { clearTimeout(timeout); controller.abort() }
    }

    // Exercise the same application's documented opt-out as a negative
    // control, then restore the original setting. No protected run uses it.
    process.env.ALLOW_PRIVATE_NETWORK_ACCESS = 'true'
    const unsafe = application.createFetcher({ unsafeControl: true })
    const applicationControl = await measureClient(adaptFetcher(unsafe), range, controls, runScan, { positiveControl: isolated })
    assert(applicationControl.results.every(row => row.verdict === 'REACHED' && row.internalHits > 0))
    const lateErrorControl = await measureClient(adaptFetcher(application.createFetcher({ unsafeControl: true, lateErrorControl: true })),
      range, [DIRECT_PROBES[0]], runScan, { positiveControl: false })
    assert.equal(lateErrorControl.reached, 1)
    assert.equal(lateErrorControl.results[0].internalHits, 1)
    assert.match(lateErrorControl.results[0].note, /before the client reported an error/)

    return {
      environment: environment(), application: application.sourceInfo,
      mode: isolated ? 'isolated-address-and-redirect' : 'direct-only',
      configuration: { api: 'safeFetch()', privateNetworkAccess: false, proxy: false,
        replacedResolver: false, replacedFetch: false, timeoutMs: 5000 },
      scope: { addressCases: probes.length, dnsRebinding: false, tls: false, proxy: false,
        bodyLimits: false, fullApplicationBoot: false, browserWorker: false },
      nativeControl, applicationControl, allowedRedirect, lateErrorControl, scan,
      exitCode: gateScan(scan),
    }
  } finally {
    if (previousOptOut === undefined) delete process.env.ALLOW_PRIVATE_NETWORK_ACCESS
    else process.env.ALLOW_PRIVATE_NETWORK_ACCESS = previousOptOut
    if (contentServer?.listening) {
      contentServer.closeAllConnections()
      await new Promise((resolve, reject) => contentServer.close(error => error ? reject(error) : resolve()))
    }
    await range.close()
  }
}

try {
  const report = await main()
  console.log(JSON.stringify(report, null, 2))
  process.exitCode = report.exitCode
} catch (error) {
  console.log(JSON.stringify({ environment: environment(), exitCode: 2, error: error instanceof Error ? error.message : String(error) }, null, 2))
  process.exitCode = 2
}
