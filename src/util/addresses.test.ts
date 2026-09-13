import { describe, expect, it } from 'vitest'
import { classifyAddress, isForbiddenAddress, NotAnIpAddressError } from './addresses.js'

describe('classifyAddress', () => {
  const cases: ReadonlyArray<[string, string]> = [
    ['127.0.0.1', 'loopback'],
    ['127.9.9.9', 'loopback'],
    ['169.254.169.254', 'link-local'],
    ['10.0.0.1', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.254', 'private'],
    ['192.168.1.1', 'private'],
    ['100.64.0.1', 'private'],
    ['0.0.0.0', 'unspecified'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'broadcast'],
    ['93.184.216.34', 'public'],
    ['172.32.0.1', 'public'],
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fe80::1', 'link-local'],
    ['fd00::1', 'unique-local'],
    ['ff02::1', 'multicast'],
    ['2606:4700:4700::1111', 'public'],
  ]

  for (const [address, expected] of cases) {
    it(`calls ${address} ${expected}`, () => {
      expect(classifyAddress(address)).toBe(expected)
    })
  }

  it('reads both spellings of an IPv4-mapped address the same way', () => {
    expect(classifyAddress('::ffff:127.0.0.1')).toBe('loopback')
    expect(classifyAddress('::ffff:7f00:1')).toBe('loopback')
    expect(classifyAddress('::ffff:10.0.0.1')).toBe('private')
  })

  it('refuses a hostname, because a name has no class until it resolves', () => {
    expect(() => classifyAddress('example.com')).toThrow(NotAnIpAddressError)
  })
})

describe('isForbiddenAddress', () => {
  it('forbids everything that is not public', () => {
    expect(isForbiddenAddress('127.0.0.1')).toBe(true)
    expect(isForbiddenAddress('169.254.169.254')).toBe(true)
    expect(isForbiddenAddress('::1')).toBe(true)
  })

  it('allows a public address', () => {
    expect(isForbiddenAddress('93.184.216.34')).toBe(false)
    expect(isForbiddenAddress('2606:4700:4700::1111')).toBe(false)
  })
})
