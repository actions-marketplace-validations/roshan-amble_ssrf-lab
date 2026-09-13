import { describe, expect, it } from 'vitest'
import { PolicyRefusal, type FetchOutcome, type HttpClient } from '../adapters/types.js'
import { CANARY_INTERNAL_SECRET } from '../range/canaries.js'
import type { AttackRange } from '../range/server.js'
import { runScan } from './run.js'

/** A range that is never started. The stubs below never open a socket. */
const fakeRange: AttackRange = {
  origin: 'http://127.0.0.1:1111',
  port: 1111,
  internalOrigin: 'http://127.0.0.1:2222',
  internalPort: 2222,
  url: (path: string) => `http://127.0.0.1:1111${path}`,
  // The stubs never open a socket, so the internal service is never hit.
  internalHits: () => 0,
  close: async () => {},
}

const reachedOutcome: FetchOutcome = {
  status: 200,
  bytesRead: 64 * 1024 * 1024,
  bodySample: CANARY_INTERNAL_SECRET,
  hops: Array.from({ length: 11 }, (_, index) => `http://127.0.0.1:1111/hop/${index}`),
  stoppedByHarness: false,
}

function stub(name: string, behaviour: () => Promise<FetchOutcome>, connectHook = true): HttpClient {
  return { name, supportsConnectHook: connectHook, fetch: behaviour }
}

describe('runScan', () => {
  it('calls a refusal BLOCKED, and keeps the reason', async () => {
    const client = stub('refuses everything', async () => {
      throw new PolicyRefusal('forbidden-address', '127.0.0.1 is loopback')
    })

    const scan = await runScan(client, fakeRange)

    expect(scan.blocked).toBe(scan.results.length)
    expect(scan.results[0]?.note).toContain('forbidden-address')
  })

  it('calls a hit REACHED', async () => {
    const client = stub('reaches everything', async () => reachedOutcome)

    const scan = await runScan(client, fakeRange)

    expect(scan.reached).toBe(scan.results.length)
  })

  it('calls a network failure LUCKY where nothing can be measured', async () => {
    const client = stub('never gets through', async () => {
      const error: NodeJS.ErrnoException = new Error('connect ECONNREFUSED')
      error.code = 'ECONNREFUSED'
      throw error
    })

    const scan = await runScan(client, fakeRange)
    const linkLocal = scan.results.find((row) => row.probeId === 'redirect-link-local')

    expect(scan.blocked).toBe(0)
    expect(linkLocal?.verdict).toBe('LUCKY')
  })

  it('calls it PREVENTED where the internal service can prove the attack never arrived', async () => {
    const client = stub('never gets through', async () => {
      const error: NodeJS.ErrnoException = new Error('connect ECONNREFUSED')
      error.code = 'ECONNREFUSED'
      throw error
    })

    const scan = await runScan(client, fakeRange)
    const loopback = scan.results.find((row) => row.probeId === 'redirect-loopback')

    expect(loopback?.verdict).toBe('PREVENTED')
    expect(loopback?.note).toContain('saw no request')
  })

  it('reads the cause chain, so a redirect cap inside fetch is not called luck', async () => {
    const client = stub('has its own redirect cap', async () => {
      throw new Error('fetch failed', { cause: new Error('redirect count exceeded') })
    })

    const scan = await runScan(client, fakeRange)
    const loop = scan.results.find((row) => row.probeId === 'redirect-loop')

    expect(loop?.verdict).toBe('BLOCKED')
    expect(loop?.note).toContain('redirect count exceeded')
  })

  it('marks the rebinding probe NOT-APPLICABLE when the client has no connect hook', async () => {
    const client = stub('no hook', async () => reachedOutcome, false)

    const scan = await runScan(client, fakeRange)
    const rebind = scan.results.find((row) => row.probeId === 'dns-rebind')

    expect(rebind?.verdict).toBe('NOT-APPLICABLE')
  })
})
