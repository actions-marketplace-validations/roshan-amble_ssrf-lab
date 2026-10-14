import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { DIRECT_PROBES, PROBES, startAttackRange, runScan, plainFetch } from '../../dist/index.js'
import { environment, measureClient, pinnedVersion } from '../../scripts/integration-evidence.mjs'
import { createClient, targets } from './adapters.mjs'

const directOnly = process.argv.includes('--direct-only')
const packages = Object.fromEntries(targets.map(target => [target.package,
  pinnedVersion(new URL(`./node_modules/${target.package}/package.json`, import.meta.url), target.version)]))
const range = await startAttackRange({ publicAddress: !directOnly })
const probes = directOnly ? DIRECT_PROBES : [...DIRECT_PROBES, ...PROBES.filter(probe =>
  probe.internalTarget || probe.id === 'redirect-link-local' || probe.id === 'redirect-private' || probe.id === 'redirect-loop')]
try {
  const scans = []
  for (const target of targets) {
    scans.push(await measureClient(createClient(target), range, probes, runScan, {
      positiveControl: !directOnly, notApplicable: target.notApplicable,
    }))
  }
  const negativeControl = await measureClient(plainFetch, range,
    probes.filter(probe => probe.internalTarget && !probe.needsConnectHook), runScan, { positiveControl: !directOnly })
  console.log(JSON.stringify({
    environment: environment(), packages,
    lockfileSha256: createHash('sha256').update(readFileSync(new URL('./package-lock.json', import.meta.url))).digest('hex'),
    configuration: { directOnly, policy: 'upstream defaults, no allowlists', harnessTimeoutMs: 5000, harnessMaxBytes: 1048576 },
    limitations: ['Address and redirect probes only; no response-resource-limit claim.', 'No injected resolver or TLS coverage.', 'ssrf-safe-fetch explicitly excludes TEST-NET addresses; that case is N/A.'],
    scans, negativeControl,
  }, null, 2))
  for (const id of directOnly ? ['direct-dotted'] : ['direct-dotted', 'redirect-loopback']) {
    assert.equal(negativeControl.results.find(result => result.probeId === id)?.verdict, 'REACHED')
  }
  for (const scan of scans) assert.equal(scan.reached, 0, `Review measured reach for ${scan.client}`)
} finally { await range.close() }
