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
    ['198.51.100.1', 'private'],
    ['240.0.0.1', 'private'],
    ['8.8.8.8', 'public'],
    ['fe80::1%eth0', 'link-local'],
    ['2001:db8::1', 'private'],
    ['2001::1', 'private'],
    ['100::1', 'private'],
    ['64:ff9b:1::1', 'private'],
    ['fec0::1', 'private'],
    ['2a00:1450:4001:80b::200e', 'public'],
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

  it('classifies the parsed address, not the text, whatever the IPv6 spelling', () => {
    // The fully written-out ::ffff:127.0.0.1. A pattern on the text misses it,
    // which is the ssrf-agent finding in this repository's own classifier.
    expect(classifyAddress('0:0:0:0:0:ffff:7f00:1')).toBe('loopback')
    expect(classifyAddress('0000:0000:0000:0000:0000:FFFF:7F00:0001')).toBe('loopback')
    expect(classifyAddress('::FFFF:127.0.0.1')).toBe('loopback')
    expect(classifyAddress('0:0:0:0:0:0:0:1')).toBe('loopback')
  })

  it('judges an IPv6 address that carries an IPv4 address by that IPv4 address', () => {
    expect(classifyAddress('::ffff:0:7f00:1')).toBe('loopback') // IPv4-translated
    expect(classifyAddress('::7f00:1')).toBe('loopback') // IPv4-compatible
    expect(classifyAddress('::127.0.0.1')).toBe('loopback')
    expect(classifyAddress('64:ff9b::7f00:1')).toBe('loopback') // NAT64
    expect(classifyAddress('64:ff9b::a9fe:a9fe')).toBe('link-local')
    expect(classifyAddress('2002:7f00:1::')).toBe('loopback') // 6to4
    expect(classifyAddress('64:ff9b::5db8:d822')).toBe('public') // NAT64 of 93.184.216.34
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
