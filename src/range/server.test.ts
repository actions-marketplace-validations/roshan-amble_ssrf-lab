import { gunzipSync } from 'node:zlib'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { BOMB_EXPANDED_BYTES, decompressionBomb } from './bomb.js'
import { CANARY_BOMB_TAIL, CANARY_INTERNAL_SECRET } from './canaries.js'
import { INTERNAL_PATH, RANGE_PATHS, startAttackRange, type AttackRange } from './server.js'

describe('attack range', () => {
  let range: AttackRange

  beforeAll(async () => {
    range = await startAttackRange()
  })

  afterAll(async () => {
    await range.close()
  })

  it('runs the internal service on its own origin, so a hit cannot be an accident', async () => {
    expect(range.internalOrigin).not.toBe(range.origin)
    const response = await fetch(`${range.internalOrigin}${INTERNAL_PATH}`)
    expect(await response.text()).toBe(CANARY_INTERNAL_SECRET)
  })

  it('points the loopback redirect at the internal service', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectLoopback), { redirect: 'manual' })
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toBe(`${range.internalOrigin}${INTERNAL_PATH}`)
  })

  it('writes the decimal form of 127.0.0.1, which a string compare does not recognise', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectDecimalLoopback), { redirect: 'manual' })
    const raw = response.headers.get('location') ?? ''

    // The header carries the decimal form. The parser is what turns it into an
    // address, which is why a control must read the parsed host, not the text.
    expect(raw).toContain('2130706433')

    const location = new URL(raw)
    expect(location.hostname).toBe('127.0.0.1')
    expect(Number(location.port)).toBe(range.internalPort)
  })

  it('sends the metadata address, which is the classic SSRF target', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectLinkLocal), { redirect: 'manual' })
    expect(response.headers.get('location')).toContain('169.254.169.254')
  })

  it('sends a documentation address, so no real device on this network is touched', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectPrivate), { redirect: 'manual' })
    expect(response.headers.get('location')).toBe('http://198.51.100.1/')
  })

  it('puts credentials in a redirect target', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectCredentials), { redirect: 'manual' })
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.username).toBe('lab')
    expect(location.password).toBe('s3cr3t')
    expect(Number(location.port)).toBe(range.internalPort)
  })

  it('keeps the redirect loop on the public origin, so it tests the hop cap alone', async () => {
    const response = await fetch(range.url(RANGE_PATHS.redirectLoop), { redirect: 'manual' })
    expect(response.headers.get('location')).toBe(RANGE_PATHS.redirectLoop)
  })

  it('serves a bomb that is small on the wire and large in memory', () => {
    const compressed = decompressionBomb()
    const expanded = gunzipSync(compressed)

    expect(compressed.byteLength).toBeLessThan(1024 * 1024)
    expect(expanded.byteLength).toBe(BOMB_EXPANDED_BYTES)
    expect(expanded.subarray(-CANARY_BOMB_TAIL.length).toString()).toBe(CANARY_BOMB_TAIL)
  })

  it('declares the bomb as gzip, so a client decompresses it without asking', async () => {
    const response = await fetch(range.url(RANGE_PATHS.payloadBomb), { redirect: 'manual' })
    expect(response.headers.get('content-encoding')).toBe('gzip')
    await response.body?.cancel()
  })

  it('starts a body with no end and no length', async () => {
    const controller = new AbortController()
    const response = await fetch(range.url(RANGE_PATHS.payloadEndless), { signal: controller.signal })
    const reader = response.body?.getReader()
    const first = await reader?.read()

    expect(first?.done).toBe(false)
    expect(response.headers.get('content-length')).toBeNull()

    controller.abort()
  })
})
