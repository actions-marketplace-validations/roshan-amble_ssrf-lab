import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { DIRECT_PROBES, PROBES, PolicyRefusal, plainFetch, runScan, startAttackRange } from '../../dist/index.js'
import { environment, measureClient } from '../../scripts/integration-evidence.mjs'

const SOURCE = '4ce9a53f45baf99f3a0bd00a26f82b47c7eea031'
async function main() {
  const { values } = parseArgs({ options: {
    module: { type: 'string' }, 'direct-only': { type: 'boolean', default: false },
  } })
  assert(values.module, 'Pass --module /path/to/linkpeek/dist/index.js')
  const modulePath = resolve(values.module)
  const sourceRoot = resolve(dirname(modulePath), '..')
  const metadata = JSON.parse(readFileSync(resolve(sourceRoot, 'package.json'), 'utf8'))
  assert.equal(metadata.name, 'linkpeek')
  assert.equal(metadata.version, '2.1.5')
  const sourceCommit = execFileSync('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
  assert.equal(sourceCommit, SOURCE, 'The consumer source must match the measured revision')

  // Verify containment before importing the consumer or starting any request.
  const isolated = !values['direct-only']
  const range = await startAttackRange({ publicAddress: isolated })
  let htmlServer
  try {
    const { preview, LinkpeekError } = await import(pathToFileURL(modulePath).href)
    const makeClient = ({ unsafe = false, failAfterResponse = false } = {}) => ({
      name: failAfterResponse ? 'linkpeek opt-out, then client error' : 'linkpeek preview() public API',
      supportsConnectHook: false,
      supportsLoopbackOrigin: false,
      async fetch(url) {
        try {
          const result = await preview(url, { timeout: 5000, ...(unsafe ? { allowPrivateIPs: true } : {}) })
          if (failAfterResponse) throw new Error('Deliberate control error after the preview request')
          // preview() exposes parsed metadata, not raw HTTP body bytes. These
          // placeholders are not body measurements; only internal-target probes
          // are selected, and their verdicts use the independent hit counter.
          return { status: result.statusCode, bytesRead: 0, bodySample: '', hops: [url, result.url], stoppedByHarness: false }
        } catch (error) {
          if (error instanceof LinkpeekError && error.code === 'PRIVATE_NETWORK_BLOCKED') {
            throw new PolicyRefusal('forbidden-address', 'linkpeek PRIVATE_NETWORK_BLOCKED')
          }
          throw error
        }
      },
    })
    const client = makeClient()
    const redirects = PROBES.filter(probe => ['redirect-loopback', 'redirect-decimal-loopback'].includes(probe.id))
    // Credentials are a separate upstream input policy, not an address refusal.
    const probes = [...DIRECT_PROBES.filter(probe => probe.id !== 'direct-credentials'), ...(isolated ? redirects : [])]
    const controlProbes = [DIRECT_PROBES[0], ...(isolated ? [redirects[0]] : [])]
    const negativeControl = await measureClient(plainFetch, range, controlProbes, runScan, { positiveControl: false })
    assert(negativeControl.results.every(row => row.verdict === 'REACHED' && row.internalHits > 0), 'Unsafe control did not reach')

    let positiveControl = null
    let metadataControl = null
    if (isolated) {
      const before = range.publicHits()
      const result = await preview(range.origin, { timeout: 5000 })
      positiveControl = { status: result.statusCode, publicHits: range.publicHits() - before, finalUrl: result.url }
      assert.equal(positiveControl.status, 200)
      assert.equal(positiveControl.publicHits, 1)
      assert.equal(new URL(result.url).origin, range.origin)

      // The consumer should also perform its actual job: parse a local HTML
      // preview and follow an allowed same-origin redirect before any refusal
      // can count as useful coverage.
      let articleHits = 0
      let redirectHits = 0
      htmlServer = createServer((request, response) => {
        if (request.url === '/redirect') {
          redirectHits++
          response.writeHead(302, { location: '/article' }).end()
        } else {
          articleHits++
          response.writeHead(200, { 'content-type': 'text/html' })
            .end('<html><head><title>SSRF Lab preview control</title></head><body>Local fixture</body></html>')
        }
      })
      await new Promise((resolve, reject) => {
        htmlServer.once('error', reject)
        htmlServer.listen(0, new URL(range.origin).hostname, resolve)
      })
      const htmlOrigin = `http://${new URL(range.origin).hostname}:${htmlServer.address().port}`
      const direct = await preview(`${htmlOrigin}/article`, { timeout: 5000 })
      const redirected = await preview(`${htmlOrigin}/redirect`, { timeout: 5000 })
      assert.equal(direct.statusCode, 200)
      assert.equal(direct.title, 'SSRF Lab preview control')
      assert.equal(redirected.statusCode, 200)
      assert.equal(redirected.title, direct.title)
      assert.equal(redirected.url, `${htmlOrigin}/article`)
      assert.equal(articleHits, 2)
      assert.equal(redirectHits, 1)
      metadataControl = { title: direct.title, directStatus: direct.statusCode,
        redirectedStatus: redirected.statusCode, articleHits, redirectHits }
    }
    const scan = await measureClient(client, range, probes, runScan, { positiveControl: false })
    // Each redirect must enter the public fixture before its target is refused.
    for (const row of scan.results.filter(row => row.probeId.startsWith('redirect-'))) {
      assert.equal(row.publicHits, 1, 'Redirect never reached its entry fixture')
    }

    const credentialsProbe = DIRECT_PROBES.find(probe => probe.id === 'direct-credentials')
    const beforeCredentials = range.internalHits()
    let credentialError
    try { await preview(credentialsProbe.start(range), { timeout: 5000 }) }
    catch (error) { credentialError = error }
    const credentialHits = range.internalHits() - beforeCredentials
    const explicitCredentials = credentialError instanceof LinkpeekError &&
      credentialError.code === 'INVALID_URL' && credentialError.message === 'URLs with embedded credentials are not allowed'
    const credentials = {
      probeId: credentialsProbe.id, control: 'credentials-not-allowed',
      verdict: credentialHits > 0 ? 'REACHED' : explicitCredentials ? 'BLOCKED' : 'PREVENTED',
      internalHits: credentialHits, errorCode: credentialError?.code ?? null,
    }

    // Prove that a parsed-metadata API's later exception cannot conceal reach.
    const lateErrorControl = await measureClient(makeClient({ unsafe: true, failAfterResponse: true }),
      range, [DIRECT_PROBES[0]], runScan, { positiveControl: false })
    assert.equal(lateErrorControl.reached, 1)
    assert.equal(lateErrorControl.results[0].internalHits, 1)
    assert.match(lateErrorControl.results[0].note, /before the client reported an error/)

    const exitCode = scan.reached > 0 || credentials.verdict === 'REACHED' ? 1 :
      scan.results.every(row => row.verdict === 'BLOCKED' && row.internalHits === 0) && credentials.verdict === 'BLOCKED' ? 0 : 2
    return {
      environment: environment(), package: { name: metadata.name, version: metadata.version, sourceCommit },
      mode: isolated ? 'isolated-address-and-redirect' : 'direct-only',
      scope: { addressCases: probes.length, credentialCases: 1, dnsRebinding: false, tls: false, bodyLimits: false, rawResponseBodyObservable: false },
      configuration: { api: 'preview()', privateIPsAllowed: false, injectedFetch: false, timeoutMs: 5000 },
      positiveControl, metadataControl, negativeControl, scan, credentials, lateErrorControl, exitCode,
    }
  } finally {
    if (htmlServer?.listening) {
      htmlServer.closeAllConnections()
      await new Promise((resolve, reject) => htmlServer.close(error => error ? reject(error) : resolve()))
    }
    await range.close()
  }
}

try {
  const report = await main()
  console.log(JSON.stringify(report, null, 2))
  process.exitCode = report.exitCode
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  console.log(JSON.stringify({ environment: environment(), exitCode: 2, error: message }, null, 2))
  process.exitCode = 2
}
