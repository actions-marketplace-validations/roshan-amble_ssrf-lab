import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { startAttackRange, runScan, DIRECT_PROBES, PROBES } from '../../dist/index.js'
import { environment, measureClient, pinnedVersion } from '../../scripts/integration-evidence.mjs'
import { createN8nClient } from './adapter.mjs'

// The bounded direct suite is also useful on machines without namespace support.
const directOnly = process.argv.includes('--direct-only')
const packages = Object.fromEntries(Object.entries({ '@n8n/backend-network': '1.17.3', '@n8n/config': '2.41.2' }).map(
  ([name, version]) => [name, pinnedVersion(new URL(`./node_modules/${name}/package.json`, import.meta.url), version)],
))
const range = await startAttackRange({ publicAddress: !directOnly })
const probes = directOnly ? DIRECT_PROBES : [...DIRECT_PROBES, ...PROBES.filter(p =>
  p.internalTarget || p.id === 'redirect-link-local' || p.id === 'redirect-private')]
const scans = []
const negativeControls = []
try {
  for (const api of ['request', 'fetch']) {
    for (const enabled of [true, false]) {
      const client = createN8nClient({ api, enabled })
      try {
        // Never ask the negative control to contact metadata or reserved networks.
        const selected = enabled ? probes : probes.filter(p => p.internalTarget && !p.needsConnectHook)
        const measured = await measureClient(client, range, selected, runScan, { positiveControl: !directOnly })
        if (enabled) scans.push(measured)
        else negativeControls.push(measured)
      } finally {
        await client.close()
      }
    }
  }
  console.log(JSON.stringify({
    environment: environment(),
    application: { name: 'n8n', version: '2.43.5', sourceCommit: 'd811f5e87dfc164999f34d75b17017876d41a54a' },
    packages,
    lockfileSha256: createHash('sha256').update(readFileSync(new URL('./package-lock.json', import.meta.url))).digest('hex'),
    scope: 'Published OutboundHttp component APIs, not a running n8n workflow or all nodes',
    configuration: { enabled: true, allowedHostnames: [], allowedIpRanges: [], blockedIpRanges: 'upstream defaults', proxy: false, directOnly },
    limitations: ['No injected resolver in this adapter; rebinding is N/A.', 'No TLS, proxy, or response-resource-limit coverage.', 'n8n workflow nodes may choose different request paths.'],
    scans, negativeControls,
  }, null, 2))
  for (const scan of scans) {
    assert.equal(scan.reached, 0, 'Review observed reach before publishing a comparison')
    assert.equal(scan.blocked + scan.prevented + scan.notApplicable, probes.length)
    assert.equal(scan.notApplicable, directOnly ? 0 : 1)
  }
  for (const control of negativeControls) {
    for (const id of directOnly ? ['direct-dotted'] : ['direct-dotted', 'redirect-loopback']) {
      assert.equal(control.results.find(result => result.probeId === id)?.verdict, 'REACHED', `Protection-off control failed: ${id}`)
    }
  }
} finally {
  await range.close()
}
