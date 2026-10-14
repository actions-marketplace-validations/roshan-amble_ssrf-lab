import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DIRECT_PROBES, PROBES } from '../checker/probes.js'
import { runScan } from '../checker/run.js'
import { startAttackRange, type AttackRange } from '../range/server.js'
import { vercelGuardedFetch } from './vercelGuardedFetch.js'

describe('guarded-fetch with the local direct suite', () => {
  let range: AttackRange
  beforeAll(async () => { range = await startAttackRange() })
  afterAll(async () => { await range.close() })

  it('records seven named refusals and no internal requests', async () => {
    const before = range.internalHits()
    const scan = await runScan(vercelGuardedFetch, range, DIRECT_PROBES)
    expect(scan.blocked).toBe(7)
    expect(scan.reached).toBe(0)
    expect(range.internalHits()).toBe(before)
  })

  it('does not credit rejection of the entry server as a tested redirect', async () => {
    const scan = await runScan(vercelGuardedFetch, range, PROBES)
    expect(scan.notApplicable).toBe(10)
    expect(scan.blocked).toBe(0)
    expect(range.publicHits()).toBe(0)
  })
})
