import { BlockList, isIP } from 'node:net'

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

type Family = 'ipv4' | 'ipv6'

/**
 * Special-purpose ranges. The first match wins, so a range that sits inside
 * another must come first: 255.255.255.255 is inside 240.0.0.0/4.
 */
const RANGES: ReadonlyArray<readonly [cidr: string, family: Family, label: AddressClass]> = [
  ['255.255.255.255/32', 'ipv4', 'broadcast'],
  ['0.0.0.0/8', 'ipv4', 'unspecified'],
  ['127.0.0.0/8', 'ipv4', 'loopback'],
  ['169.254.0.0/16', 'ipv4', 'link-local'],
  ['10.0.0.0/8', 'ipv4', 'private'],
  ['172.16.0.0/12', 'ipv4', 'private'],
  ['192.168.0.0/16', 'ipv4', 'private'],
  // Carrier-grade NAT. Reachable inside many hosting networks.
  ['100.64.0.0/10', 'ipv4', 'private'],
  // IETF protocol assignments, documentation and benchmarking.
  ['192.0.0.0/24', 'ipv4', 'private'],
  ['192.0.2.0/24', 'ipv4', 'private'],
  ['198.18.0.0/15', 'ipv4', 'private'],
  ['198.51.100.0/24', 'ipv4', 'private'],
  ['203.0.113.0/24', 'ipv4', 'private'],
  ['224.0.0.0/4', 'ipv4', 'multicast'],
  ['240.0.0.0/4', 'ipv4', 'private'],

  ['::/128', 'ipv6', 'unspecified'],
  ['::1/128', 'ipv6', 'loopback'],
  // NAT64 for local use; the well-known prefix 64:ff9b::/96 is handled as an
  // embedded IPv4 address instead.
  ['64:ff9b:1::/48', 'ipv6', 'private'],
  // Discard-only.
  ['100::/64', 'ipv6', 'private'],
  // IETF protocol assignments (Teredo, benchmarking, ...) and documentation,
  // the IPv6 counterparts of the IPv4 ranges above.
  ['2001::/23', 'ipv6', 'private'],
  ['2001:db8::/32', 'ipv6', 'private'],
  ['fc00::/7', 'ipv6', 'unique-local'],
  ['fe80::/10', 'ipv6', 'link-local'],
  // Deprecated site-local, the predecessor of fc00::/7.
  ['fec0::/10', 'ipv6', 'private'],
  ['ff00::/8', 'ipv6', 'multicast'],
]

/**
 * `BlockList` compares parsed numbers, not text, so no spelling of an address
 * can slip past a pattern. That is the gap this file once shared with
 * `ssrf-agent`: a regex on the text missed `0:0:0:0:0:ffff:7f00:1`.
 */
const COMPILED = RANGES.map(([cidr, family, label]) => {
  const [network = '', prefix = ''] = cidr.split('/')
  const list = new BlockList()
  list.addSubnet(network, Number(prefix), family)
  return { family, label, list }
})

/**
 * Classify one IP address literal.
 *
 * The caller passes an address, never a hostname: a hostname has no class
 * until it is resolved, and resolving it is the caller's decision.
 */
export function classifyAddress(address: string): AddressClass {
  const family = isIP(address)
  if (family === 4) return matchRange(address, 'ipv4')
  if (family === 6) return classifyIpv6(address)
  throw new NotAnIpAddressError(address)
}

/** True when an address must not be reached by a fetcher of untrusted URLs. */
export function isForbiddenAddress(address: string): boolean {
  return classifyAddress(address) !== 'public'
}

function matchRange(address: string, family: Family): AddressClass {
  for (const range of COMPILED) {
    if (range.family === family && range.list.check(address, family)) return range.label
  }
  return 'public'
}

function classifyIpv6(address: string): AddressClass {
  const { canonical, hextets } = parseIpv6(address)

  // An address that carries an IPv4 address is judged by that IPv4 address,
  // because that is where a connection to it can end up.
  const embedded = embeddedIpv4(hextets)
  if (embedded !== null) return matchRange(embedded, 'ipv4')

  return matchRange(canonical, 'ipv6')
}

/**
 * Parse an IPv6 literal into its 8 groups.
 *
 * The WHATWG URL parser validates the address and writes it in one canonical
 * form: lowercase, at most one `::`, and any dotted IPv4 tail rewritten in hex.
 * A zone ID (`%eth0`) names an interface, not a different address.
 */
function parseIpv6(address: string): { canonical: string; hextets: number[] } {
  const bare = address.split('%')[0] ?? ''
  let canonical: string
  try {
    canonical = new URL(`http://[${bare}]/`).hostname.slice(1, -1)
  } catch {
    throw new NotAnIpAddressError(address)
  }

  const [head = '', tail] = canonical.split('::')
  const left = head === '' ? [] : head.split(':')
  const right = tail === undefined || tail === '' ? [] : tail.split(':')
  const zeros = tail === undefined ? [] : Array<string>(8 - left.length - right.length).fill('0')
  const hextets = [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16))

  return { canonical, hextets }
}

/**
 * The IPv4 address inside an IPv6 address, for the forms that carry one.
 *
 * - `::ffff:a.b.c.d`     IPv4-mapped
 * - `::ffff:0:a.b.c.d`   IPv4-translated
 * - `::a.b.c.d`          IPv4-compatible (deprecated); `::` and `::1` excluded
 * - `64:ff9b::a.b.c.d`   NAT64 well-known prefix
 * - `2002:aabb:ccdd::`   6to4
 */
function embeddedIpv4(h: readonly number[]): string | null {
  const zero = (from: number, to: number): boolean => h.slice(from, to).every((group) => group === 0)
  const dotted = (high = 0, low = 0): string =>
    [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.')

  if (zero(0, 5) && h[5] === 0xffff) return dotted(h[6], h[7])
  if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) return dotted(h[6], h[7])
  if (zero(0, 6) && !(h[6] === 0 && (h[7] ?? 0) <= 1)) return dotted(h[6], h[7])
  if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return dotted(h[6], h[7])
  if (h[0] === 0x2002) return dotted(h[1], h[2])

  return null
}
