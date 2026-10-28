import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { globalAgent, get } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertIsolatedNetwork, guardedFetch, PolicyRefusal } from '../../dist/index.js'
import { readCapped } from '../../dist/adapters/internal.js'
import { startHttpsFixture, PUBLIC_HOST, PRIVATE_HOST, PUBLIC_CANARY, INTERNAL_CANARY } from './fixture.mjs'

const TLS_ERRORS = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID',
])

// Start a new Node process: NODE_EXTRA_CA_CERTS is read at process launch.
// No system trust store changes, committed keys, or disabled verification.
if (process.argv[2] !== '--child') {
  let directory
  try {
    assertIsolatedNetwork()
    assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0', 'TLS verification must be enabled')
    directory = mkdtempSync(join(tmpdir(), 'ssrf-lab-https-'))
    const openssl = args => execFileSync('openssl', args, { cwd: directory, stdio: 'pipe', timeout: 15_000 })
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
      '-days', '2', '-subj', '/CN=ssrf-lab temporary fixture CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr',
      '-subj', `/CN=${PUBLIC_HOST}`])
    writeFileSync(join(directory, 'server.ext'), [
      'basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth', `subjectAltName=DNS:${PUBLIC_HOST},DNS:${PRIVATE_HOST}`, '',
    ].join('\n'))
    openssl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
      '-out', 'server.pem', '-days', '2', '-extfile', 'server.ext'])
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--child', directory], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: join(directory, 'ca.pem') },
      stdio: 'inherit', timeout: 60_000,
    })
    if (child.error) throw child.error
    process.exitCode = child.status ?? 2
  } catch (error) {
    console.error(`HTTPS fixture setup failed: ${error.message}`)
    process.exitCode = 2
  } finally {
    if (directory) rmSync(directory, { recursive: true, force: true })
  }
} else {
  await verify(process.argv[3])
}

async function verify(directory) {
  let fixture
  const results = []
  try {
    assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0', 'TLS verification must be enabled')
    fixture = await startHttpsFixture({
      key: readFileSync(join(directory, 'server.key')),
      cert: readFileSync(join(directory, 'server.pem')),
    })
    const guarded = (url, lookup = fixture.lookup) => guardedFetch.fetch(url, { lookup, timeoutMs: 3000 })
    const unsafe = (url, options = {}) => readHttps(url, { lookup: fixture.lookup, ...options })
    const zeroInternal = row => assert.deepEqual(row.internal, { tcpConnections: 0, tlsConnections: 0, requests: 0 })
    const blocked = row => {
      assert.equal(row.verdict, 'BLOCKED')
      assert.equal(row.error.reason, 'forbidden-address')
      zeroInternal(row)
    }
    const reached = row => {
      assert.equal(row.verdict, 'REACHED')
      assert.equal(row.internal.requests, 1)
      assert.equal(row.internal.tlsConnections, 1)
    }
    const tlsFailure = row => {
      assert.equal(row.verdict, 'TLS_FAILURE')
      assert.equal(row.public.tcpConnections, 1)
      assert.equal(row.public.requests, 0)
      zeroInternal(row)
    }
    async function check(name, attempt, validate) {
      const row = await observe(fixture, attempt)
      try { validate(row); row.passed = true }
      catch (error) { row.passed = false; row.failure = error.message }
      results.push({ name, ...row })
    }

    await check('allowed HTTPS with trusted CA and matching hostname', () => guarded(fixture.origin), row => {
      assert.equal(row.verdict, 'ALLOWED')
      assert.equal(row.status, 200)
      assert.equal(row.bodySample, PUBLIC_CANARY)
      assert.equal(row.public.requests, 1)
      assert.equal(row.public.tlsConnections, 1)
      zeroInternal(row)
    })
    await check('private hostname refused before connecting', () => guarded(fixture.internalOrigin), blocked)
    await check('HTTPS redirect into private hostname refused', () => guarded(`${fixture.origin}/redirect/private`), row => {
      blocked(row)
      assert.equal(row.public.requests, 1)
    })
    await check('same public hostname with private DNS answer refused', () => guarded(fixture.origin, fixture.privateAnswer), row => {
      blocked(row)
      assert(row.dnsQueries > 0)
      assert.equal(row.public.tcpConnections, 0)
    })
    await check('unsafe HTTPS direct control reaches the internal counter', () => unsafe(fixture.internalOrigin), row => {
      reached(row)
      assert.equal(row.bodySample, INTERNAL_CANARY)
    })
    await check('unsafe HTTPS redirect control reaches the internal counter', () => unsafe(`${fixture.origin}/redirect/private`), row => {
      reached(row)
      assert.equal(row.public.requests, 1)
    })
    await check('unsafe same-hostname private DNS control reaches the counter', () => unsafe(fixture.origin, { lookup: fixture.privateAnswer }), reached)
    await check('a policy error after an internal request remains REACHED', async () => {
      await unsafe(fixture.internalOrigin)
      throw new PolicyRefusal('forbidden-address', 'deliberate late refusal control')
    }, row => {
      reached(row)
      assert.equal(row.error.name, 'PolicyRefusal')
    })
    await check('untrusted CA is a TLS failure, not a policy block', () => unsafe(fixture.origin, { ca: [] }), tlsFailure)
    await check('hostname mismatch is a TLS failure, not a policy block', () => guarded(fixture.wrongHostnameOrigin), row => {
      tlsFailure(row)
      assert.equal(row.error.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
    })

    const failed = results.filter(row => !row.passed).length
    console.log(JSON.stringify({
      node: process.version,
      scope: { tls: true, defaultPort: 443, injectedResolver: true, realDnsRebinding: false,
        applicationUnderTest: false, client: guardedFetch.name },
      passed: results.length - failed, failed, results,
    }, null, 2))
    process.exitCode = failed === 0 ? 0 : 1
  } catch (error) {
    console.error(`HTTPS fixture could not establish coverage: ${error.message}`)
    process.exitCode = 2
  } finally {
    globalAgent.destroy()
    await fixture?.close()
  }
}

async function observe(fixture, attempt) {
  const before = fixture.snapshot()
  let value, error
  try { value = await attempt() }
  catch (caught) { error = caught }
  // Each known control finishes its body or rejects before it settles. Destroy
  // idle pooled sockets and wait for server-side close before the next case.
  globalAgent.destroy()
  await fixture.drain()
  const after = fixture.snapshot()
  const difference = side => Object.fromEntries(Object.keys(after[side]).map(key => [key, after[side][key] - before[side][key]]))
  const internal = difference('internal')
  const verdict = internal.requests > 0 ? 'REACHED'
    : internal.tcpConnections > 0 ? 'CONTACTED'
      : error instanceof PolicyRefusal ? 'BLOCKED'
        : TLS_ERRORS.has(error?.code) ? 'TLS_FAILURE'
          : error ? 'INCONCLUSIVE' : 'ALLOWED'
  return {
    verdict, public: difference('public'), internal, dnsQueries: after.dnsQueries - before.dnsQueries,
    ...(value ? { status: value.status, bodySample: value.bodySample } : {}),
    ...(error ? { error: { name: error.name, code: error.code, reason: error.reason } } : {}),
  }
}

/** Deliberately unguarded local control; certificate verification stays enabled. */
async function readHttps(url, { lookup, ca } = {}) {
  const signal = AbortSignal.timeout(3000)
  let target = url
  for (let hop = 0; hop < 4; hop += 1) {
    const response = await new Promise((resolve, reject) => {
      const request = get(target, { lookup, signal, agent: false, ...(ca === undefined ? {} : { ca }) }, resolve)
      request.once('error', reject)
    })
    const body = await readCapped(response, 8192)
    if (response.statusCode === 302 && response.headers.location) {
      target = new URL(response.headers.location, target).href
      continue
    }
    return { status: response.statusCode, bodySample: body.sample }
  }
  throw new Error('Unsafe fixture control exceeded its redirect bound')
}
