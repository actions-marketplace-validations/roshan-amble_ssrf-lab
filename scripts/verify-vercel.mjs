import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import {
  startAttackRange, runScan, DIRECT_PROBES, PROBES, plainFetch, vercelGuardedFetch,
} from '../dist/index.js'
import { environment, measureClient, pinnedVersion } from './integration-evidence.mjs'

const version = pinnedVersion(new URL('../node_modules/guarded-fetch/package.json', import.meta.url), '0.1.5')
const range = await startAttackRange({ publicAddress: true })
try {
  const scan = await measureClient(vercelGuardedFetch, range, [...DIRECT_PROBES, ...PROBES], runScan)
  const controlProbes = [...DIRECT_PROBES, ...PROBES.filter(p => p.internalTarget && !p.needsConnectHook)]
  const negative = await measureClient(plainFetch, range, controlProbes, runScan)
  for (const id of ['direct-dotted', 'redirect-loopback']) {
    assert.equal(negative.results.find(result => result.probeId === id)?.verdict, 'REACHED', `Unsafe control failed: ${id}`)
  }
  // Preserve evidence before applying the release gate.
  console.log(JSON.stringify({
    environment: environment(),
    package: { name: 'guarded-fetch', version },
    lockfileSha256: createHash('sha256').update(readFileSync(new URL('../package-lock.json', import.meta.url))).digest('hex'),
    configuration: { api: 'guardedFetch + readBodyAsText', timeoutMs: 5000, slowDripTimeoutMs: 4000, maxResponseBytes: 1048576 },
    limitations: ['No injectable base DNS resolver; simulated rebinding is N/A.', 'Plain HTTP only; no TLS coverage.', 'Initial and final URLs are observable, not every intermediate hop.'],
    scans: [scan], negativeControl: negative,
  }, null, 2))
  assert.equal(scan.reached, 0, 'Review observed reach before publishing a comparison')
  assert.equal(scan.blocked, 16)
  assert.equal(scan.notApplicable, 1)
} finally {
  await range.close()
}
