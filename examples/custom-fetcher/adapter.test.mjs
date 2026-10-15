import assert from 'node:assert/strict'
import { test } from 'node:test'
import { DIRECT_PROBES, PolicyRefusal, startAttackRange, runScan } from '../../dist/index.js'
import { measureClient } from '../../scripts/integration-evidence.mjs'
import { adaptFetcher, gateScan } from './adapter.mjs'

test('a real request is REACHED even when the application throws a policy error afterward', async () => {
  const range = await startAttackRange()
  try {
    const client = adaptFetcher({
      async fetchUrl(url, { signal }) { await (await fetch(url, { signal })).text(); throw new Error('late refusal') },
      classifyRefusal: () => 'forbidden-address',
    })
    const scan = await runScan(client, range, [DIRECT_PROBES[0]])
    assert.equal(scan.reached, 1)
    assert.equal(range.internalHits(), 1)
    assert.equal(gateScan(scan), 1)
  } finally { await range.close() }
})

test('network errors remain inconclusive; explicit application refusals pass the direct case', async () => {
  const range = await startAttackRange()
  try {
    for (const [classifyRefusal, verdict, exitCode] of [
      [() => undefined, 'PREVENTED', 2], [() => 'forbidden-address', 'BLOCKED', 0],
    ]) {
      const client = adaptFetcher({ fetchUrl: async () => { throw new Error('application error') }, classifyRefusal })
      const scan = await runScan(client, range, [DIRECT_PROBES[0]])
      assert.equal(scan.results[0].verdict, verdict)
      assert.equal(gateScan(scan), exitCode)
      assert.equal(range.internalHits(), 0)
    }
  } finally { await range.close() }
})

test('a client that refuses every URL fails the allowed-entry control', async () => {
  const range = await startAttackRange()
  try {
    const denyAll = adaptFetcher({ fetchUrl: async () => { throw new Error('deny all') }, classifyRefusal: () => 'forbidden-address' })
    await assert.rejects(measureClient(denyAll, range, [DIRECT_PROBES[0]], runScan), /explicit address-policy refusal/)
    assert.equal(range.publicHits(), 0)
  } finally { await range.close() }
})

test('a named deadline does not pass an address-policy regression gate', async () => {
  const range = await startAttackRange()
  try {
    const client = adaptFetcher({ fetchUrl: async () => { throw new PolicyRefusal('deadline', 'expired') } })
    const scan = await runScan(client, range, [DIRECT_PROBES[0]])
    assert.equal(gateScan(scan), 2)
  } finally { await range.close() }
})

test('an unrelated success cannot satisfy the allowed-entry control', async () => {
  const range = await startAttackRange()
  try {
    const fakeSuccess = adaptFetcher({ fetchUrl: async () => new Response('cached result') })
    await assert.rejects(measureClient(fakeSuccess, range, [DIRECT_PROBES[0]], runScan), /wrong entry response/)
  } finally { await range.close() }
})

test('the adapter measures the response and cancels an overlarge stream without claiming BLOCKED', async () => {
  const client = adaptFetcher({ fetchUrl: async () => new Response('hello') })
  const response = await client.fetch('http://fixture.test')
  assert.equal(response.bytesRead, 5)
  assert.equal(response.bodySample, 'hello')
  let canceled = false
  const large = adaptFetcher({
    fetchUrl: async () => new Response(new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(65537)) },
      cancel() { canceled = true },
    })),
  })
  await assert.rejects(large.fetch('http://fixture.test'), /Harness response limit/)
  assert.equal(canceled, true)
})
