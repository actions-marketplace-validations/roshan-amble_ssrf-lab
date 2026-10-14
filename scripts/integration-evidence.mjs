import assert from 'node:assert/strict'
import { platform, release } from 'node:os'
import { readFileSync } from 'node:fs'

export function pinnedVersion(packageJson, expected) {
  const metadata = JSON.parse(readFileSync(packageJson, 'utf8'))
  assert.equal(metadata.version, expected, `${metadata.name}: installed version differs from the measured target`)
  return metadata.version
}

/** Probe one request at a time and keep both server counters beside the verdict. */
export async function measureClient(client, range, probes, runScan, { positiveControl = true, notApplicable = {} } = {}) {
  let control = null
  if (positiveControl) {
    const before = range.publicHits()
    const response = await client.fetch(range.origin)
    assert.equal(response.status, 200, `${client.name}: entry request failed`)
    assert(response.bodySample.includes('/redirect/loopback'), `${client.name}: wrong entry response`)
    assert(range.publicHits() > before, `${client.name}: entry server saw no request`)
    control = { status: response.status, publicHits: range.publicHits() - before }
  }
  const results = []
  for (const probe of probes) {
    const before = { internal: range.internalHits(), public: range.publicHits() }
    const result = Object.hasOwn(notApplicable, probe.id)
      ? { probeId: probe.id, title: probe.title, verdict: 'NOT-APPLICABLE', note: notApplicable[probe.id], durationMs: 0 }
      : (await runScan(client, range, [probe])).results[0]
    const measured = {
      ...result,
      internalHits: range.internalHits() - before.internal,
      publicHits: range.publicHits() - before.public,
    }
    // Entry refusal cannot count as coverage of a redirect or response body.
    if (positiveControl && new URL(probe.start(range)).origin === range.origin &&
        result.verdict !== 'NOT-APPLICABLE') {
      assert(measured.publicHits > 0, `${client.name}: ${probe.id} never reached the entry server`)
    }
    results.push(measured)
  }
  const count = verdict => results.filter(result => result.verdict === verdict).length
  return {
    client: client.name,
    positiveControl: control,
    results,
    blocked: count('BLOCKED'),
    prevented: count('PREVENTED'),
    reached: count('REACHED'),
    lucky: count('LUCKY'),
    notApplicable: count('NOT-APPLICABLE'),
  }
}

export function environment() {
  return { node: process.version, platform: platform(), kernel: release(), measuredAt: new Date().toISOString() }
}
