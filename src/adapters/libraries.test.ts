import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DIRECT_PROBES } from '../checker/probes.js'
import { runScan } from '../checker/run.js'
import { startAttackRange, type AttackRange } from '../range/server.js'
import { requestFilteringAgent } from './libraries.js'

describe('a third-party SSRF agent under the direct suite', () => {
  let range: AttackRange

  beforeAll(async () => {
    range = await startAttackRange()
  })

  afterAll(async () => {
    await range.close()
  })

  it(
    'request-filtering-agent blocks every spelling, and the harness reads its refusal as a control',
    async () => {
      const before = range.internalHits()
      const scan = await runScan(requestFilteringAgent, range, DIRECT_PROBES)

      // Both halves matter. The first says the harness understood the
      // library's own wording; the second says nothing arrived, measured.
      expect(scan.blocked).toBe(DIRECT_PROBES.length)
      expect(range.internalHits()).toBe(before)
    },
    120_000,
  )
})
