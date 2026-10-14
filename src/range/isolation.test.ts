import { execFileSync } from 'node:child_process'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { assertIsolatedNetwork, ISOLATED_PUBLIC_ADDRESS } from './isolation.js'

vi.mock('node:child_process', () => ({ execFileSync: vi.fn() }))

describe.skipIf(process.platform !== 'linux')('public-address isolation gate', () => {
  let links: unknown[]
  let ipv4: unknown[]
  let ipv6: unknown[]

  beforeEach(() => {
    links = [{ ifname: 'lo', flags: ['LOOPBACK', 'UP'], addr_info: [{ local: ISOLATED_PUBLIC_ADDRESS }] }]
    ipv4 = [{ dev: 'lo', dst: ISOLATED_PUBLIC_ADDRESS }]
    ipv6 = [{ dev: 'lo', dst: '::1' }]
    vi.mocked(execFileSync).mockImplementation((_command, args) =>
      JSON.stringify(args?.includes('address') ? links : args?.includes('-4') ? ipv4 : ipv6))
  })

  it('accepts a loopback-only namespace with the assigned fixture address', () => {
    expect(() => assertIsolatedNetwork()).not.toThrow()
  })

  it('refuses an external interface even if it has no default route', () => {
    links.push({ ifname: 'eth0', flags: ['UP'], addr_info: [] })
    expect(() => assertIsolatedNetwork()).toThrow('only lo')
  })

  it('refuses a missing fixture address', () => {
    links = [{ ifname: 'lo', flags: ['UP'], addr_info: [{ local: '127.0.0.1' }] }]
    expect(() => assertIsolatedNetwork()).toThrow('Assign')
  })

  it('refuses a disabled loopback interface', () => {
    links = [{ ifname: 'lo', flags: ['LOOPBACK'], addr_info: [{ local: ISOLATED_PUBLIC_ADDRESS }] }]
    expect(() => assertIsolatedNetwork()).toThrow('enabled')
  })

  it.each([
    { dev: 'eth0', dst: '10.0.0.0/8' },
    { dev: 'lo', dst: 'default' },
    { dev: 'lo', dst: '10.0.0.0/8', gateway: '127.0.0.1' },
  ])('refuses an external, default, or gateway route: %j', route => {
    ipv4.push(route)
    expect(() => assertIsolatedNetwork()).toThrow('no external routes')
  })

  it('also checks IPv6 routing', () => {
    ipv6.push({ dev: 'eth0', dst: '2001:db8::/32' })
    expect(() => assertIsolatedNetwork()).toThrow('no external routes')
  })

  it('fails closed when the network inventory cannot be read', () => {
    vi.mocked(execFileSync).mockImplementation(() => { throw new Error('permission denied') })
    expect(() => assertIsolatedNetwork()).toThrow('permission denied')
  })
})
