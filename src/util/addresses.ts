import { isIP } from 'node:net'

/**
 * Classes of IP address that matter to an SSRF control.
 * Everything that is not `public` points somewhere a fetcher of user-supplied
 * URLs has no business reaching.
 */
export type AddressClass =
  | 'loopback'
  | 'link-local'
  | 'private'
  | 'unique-local'
  | 'unspecified'
  | 'multicast'
  | 'broadcast'
  | 'public'

/** Cloud instance metadata lives here on AWS, GCP and Azure. */
export const METADATA_ADDRESS = '169.254.169.254'

export class NotAnIpAddressError extends Error {
  constructor(readonly value: string) {
    super(`not an IP address: ${value}`)
    this.name = 'NotAnIpAddressError'
  }
}

/**
 * Classify one IP address literal.
 *
 * The caller passes an address, never a hostname: a hostname has no class
 * until it is resolved, and resolving it is the caller's decision.
 */
export function classifyAddress(address: string): AddressClass {
  const family = isIP(address)
  if (family === 4) return classifyIpv4(address)
  if (family === 6) return classifyIpv6(address)
  throw new NotAnIpAddressError(address)
}

/** True when an address must not be reached by a fetcher of untrusted URLs. */
export function isForbiddenAddress(address: string): boolean {
  return classifyAddress(address) !== 'public'
}

function classifyIpv4(address: string): AddressClass {
  const octets = address.split('.').map((part) => Number.parseInt(part, 10))
  const [a = 0, b = 0, c = 0, d = 0] = octets

  if (a === 127) return 'loopback'
  if (a === 0) return 'unspecified'
  if (a === 169 && b === 254) return 'link-local'
  if (a === 10) return 'private'
  if (a === 172 && b >= 16 && b <= 31) return 'private'
  if (a === 192 && b === 168) return 'private'
  // Carrier-grade NAT. Reachable inside many hosting networks.
  if (a === 100 && b >= 64 && b <= 127) return 'private'
  // Test and documentation ranges, plus IETF protocol assignments.
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return 'private'
  if (a === 198 && (b === 18 || b === 19)) return 'private'
  if (a === 198 && b === 51 && c === 100) return 'private'
  if (a === 203 && b === 0 && c === 113) return 'private'
  if (a === 255 && b === 255 && c === 255 && d === 255) return 'broadcast'
  if (a >= 224 && a <= 239) return 'multicast'
  if (a >= 240) return 'private'

  return 'public'
}

function classifyIpv6(address: string): AddressClass {
  const normalized = address.toLowerCase().split('%')[0] ?? ''

  if (normalized === '::1') return 'loopback'
  if (normalized === '::') return 'unspecified'

  const mapped = ipv4InsideIpv6(normalized)
  if (mapped !== null) return classifyIpv4(mapped)

  const firstGroup = firstHextet(normalized)
  if (firstGroup === null) return 'public'

  // ff00::/8
  if (firstGroup >= 0xff00) return 'multicast'
  // fe80::/10
  if (firstGroup >= 0xfe80 && firstGroup <= 0xfebf) return 'link-local'
  // fc00::/7
  if (firstGroup >= 0xfc00 && firstGroup <= 0xfdff) return 'unique-local'

  return 'public'
}

/**
 * Read the IPv4 address out of an IPv4-mapped or IPv4-compatible IPv6 address.
 *
 * Both spellings reach the same host, so both must classify the same way:
 * `::ffff:127.0.0.1` and `::ffff:7f00:1` are the same loopback address.
 */
function ipv4InsideIpv6(address: string): string | null {
  const dotted = address.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
  if (dotted?.[1] !== undefined && address.includes('::')) return dotted[1]

  const hexMapped = address.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (hexMapped?.[1] === undefined || hexMapped[2] === undefined) return null

  const high = Number.parseInt(hexMapped[1], 16)
  const low = Number.parseInt(hexMapped[2], 16)
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.')
}

function firstHextet(address: string): number | null {
  const head = address.startsWith('::') ? '0' : (address.split(':')[0] ?? '')
  if (head === '') return null
  const value = Number.parseInt(head, 16)
  return Number.isNaN(value) ? null : value
}
