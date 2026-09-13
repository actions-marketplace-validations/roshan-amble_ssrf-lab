import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { PROBES } from '../checker/probes.js'
import { runScan } from '../checker/run.js'
import { startAttackRange, type AttackRange } from '../range/server.js'
import { checkThenConnect } from './checkThenConnect.js'
import { guardedFetch } from './guardedFetch.js'
import { plainFetch } from './plainFetch.js'

const SLOW = 180_000

describe('clients against the live range', () => {
  let range: AttackRange

  beforeAll(async () => {
    range = await startAttackRange()
  })

  afterAll(async () => {
    await range.close()
  })

  it(
    'the guarded client lets nothing through, and names a control every time',
    async () => {
      const scan = await runScan(guardedFetch, range)
      const leaks = scan.results.filter(
        (row) => row.verdict !== 'BLOCKED' && row.verdict !== 'PREVENTED',
      )

      expect(leaks.map((row) => `${row.probeId}: ${row.verdict}`)).toEqual([])
      expect(scan.reached).toBe(0)
    },
    SLOW,
  )

  it(
    'under rebinding the guarded client connects to the address it judged, so nothing arrives',
    async () => {
      const rebind = PROBES.filter((probe) => probe.id === 'dns-rebind')
      const before = range.internalHits()

      const scan = await runScan(guardedFetch, range, rebind)

      // The measurement, not the error text: the internal service was never
      // asked. The socket went to the public address the guard approved.
      expect(range.internalHits()).toBe(before)
      expect(scan.reached).toBe(0)
    },
    SLOW,
  )

  it(
    'under rebinding the naive client does reach the internal service',
    async () => {
      const rebind = PROBES.filter((probe) => probe.id === 'dns-rebind')
      const before = range.internalHits()

      const scan = await runScan(checkThenConnect, range, rebind)

      expect(range.internalHits()).toBe(before + 1)
      expect(scan.reached).toBe(1)
    },
    SLOW,
  )

  it(
    'the naive client loses only to rebinding, which is the whole point of it',
    async () => {
      const scan = await runScan(checkThenConnect, range)
      const reached = scan.results.filter((row) => row.verdict === 'REACHED')

      expect(reached.map((row) => row.probeId)).toEqual(['dns-rebind'])
    },
    SLOW,
  )

  it(
    'built-in fetch reaches the internal service, and cannot even take the rebinding probe',
    async () => {
      const scan = await runScan(plainFetch, range)
      const byId = new Map(scan.results.map((row) => [row.probeId, row]))

      expect(byId.get('redirect-loopback')?.verdict).toBe('REACHED')
      expect(byId.get('redirect-decimal-loopback')?.verdict).toBe('REACHED')
      expect(byId.get('decompression-bomb')?.verdict).toBe('REACHED')
      expect(byId.get('endless-body')?.verdict).toBe('REACHED')
      expect(byId.get('dns-rebind')?.verdict).toBe('NOT-APPLICABLE')

      // Its one real control is a redirect cap, and it is the only one.
      expect(byId.get('redirect-loop')?.verdict).toBe('BLOCKED')
      expect(scan.blocked).toBe(1)
    },
    SLOW,
  )
})
