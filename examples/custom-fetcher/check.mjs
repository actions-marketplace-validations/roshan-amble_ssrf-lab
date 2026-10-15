import assert from 'node:assert/strict'
import { parseArgs } from 'node:util'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { DIRECT_PROBES, PROBES, startAttackRange, runScan, renderTable } from '../../dist/index.js'
import { environment, measureClient } from '../../scripts/integration-evidence.mjs'
import { adaptFetcher, gateScan } from './adapter.mjs'

let range
let fetchModule
try {
  const { values } = parseArgs({ options: {
    module: { type: 'string' }, isolated: { type: 'boolean', default: false },
    unsafe: { type: 'boolean', default: false }, json: { type: 'boolean', default: false },
  } })
  if (values.module && values.unsafe) throw new Error('Choose either --module or --unsafe')
  // Verify isolation before importing a user module or opening any listener.
  range = await startAttackRange({ publicAddress: values.isolated })
  fetchModule = values.unsafe
    ? { name: 'native fetch: deliberately unsafe control', fetchUrl: (url, { signal }) => fetch(url, { signal }) }
    : await import(values.module ? pathToFileURL(resolve(values.module)).href : new URL('./app-fetch.mjs', import.meta.url).href)
  const client = adaptFetcher(fetchModule)
  const redirects = PROBES.filter(probe => ['redirect-loopback', 'redirect-decimal-loopback'].includes(probe.id))
  const probes = values.isolated ? [...DIRECT_PROBES, ...redirects] : DIRECT_PROBES
  const controls = [DIRECT_PROBES[0], ...(values.isolated ? [redirects[0]] : [])]
  const unsafeClient = adaptFetcher({ name: 'native fetch control', fetchUrl: (url, { signal }) => fetch(url, { signal }) })
  const negativeControl = await measureClient(unsafeClient, range, controls, runScan, { positiveControl: values.isolated })
  assert(negativeControl.results.every(row => row.verdict === 'REACHED' && row.internalHits > 0), 'Negative control did not reach the internal service')
  const scan = await measureClient(client, range, probes, runScan, { positiveControl: values.isolated })
  const exitCode = gateScan(scan)
  const report = {
    environment: environment(), mode: values.isolated ? 'isolated-address-and-redirect' : 'direct-only',
    scope: { directCases: 7, redirectCases: values.isolated ? 2 : 0, dnsRebinding: false, tls: false, bodyLimits: false },
    negativeControl, scan, exitCode,
  }
  if (values.json) console.log(JSON.stringify(report, null, 2))
  else {
    console.log(renderTable(scan))
    console.log(`\nNegative control: ${negativeControl.reached}/${controls.length} reached, as expected.`)
    console.log(values.isolated
      ? `Allowed entry: HTTP ${scan.positiveControl.status}, ${scan.positiveControl.publicHits} measured request(s).`
      : 'Direct-only smoke test. Run --isolated in CI to verify an allowed entry and two redirects.')
    console.log(`Gate exit ${exitCode}: ${['all selected cases explicitly blocked', 'an internal request was observed', 'inconclusive coverage'][exitCode]}.`)
  }
  process.exitCode = exitCode
} catch (error) {
  console.error(`Custom-fetcher check could not establish coverage: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 2
} finally {
  try { await fetchModule?.close?.() }
  catch { console.error('Application fetcher cleanup failed'); process.exitCode = 2 }
  try { await range?.close() }
  catch { console.error('Lab cleanup failed'); process.exitCode = 2 }
}
