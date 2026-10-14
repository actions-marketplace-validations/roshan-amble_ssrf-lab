import { execFileSync } from 'node:child_process'

/** This address exists only on lo inside the isolated integration namespace. */
export const ISOLATED_PUBLIC_ADDRESS = '93.184.216.34'

/** Fail closed before a listener or client can use the public-address fixture. */
export function assertIsolatedNetwork(): void {
  if (process.platform !== 'linux') throw new Error('Public-address tests require Linux network isolation')
  const links = JSON.parse(execFileSync('ip', ['-j', 'address', 'show'], { encoding: 'utf8' })) as
    { ifname: string; flags: string[]; addr_info: { local: string }[] }[]
  if (links.length !== 1 || links[0]?.ifname !== 'lo' || !links[0].flags.includes('UP')) {
    throw new Error('Public-address tests require a network namespace with only lo, enabled')
  }
  if (!links[0].addr_info.some((address) => address.local === ISOLATED_PUBLIC_ADDRESS)) {
    throw new Error(`Assign ${ISOLATED_PUBLIC_ADDRESS}/32 to lo inside the isolated namespace first`)
  }
  for (const family of ['-4', '-6']) {
    const routes = JSON.parse(execFileSync('ip', ['-j', family, 'route', 'show', 'table', 'all'], {
      encoding: 'utf8',
    })) as { dev?: string; gateway?: string; dst?: string }[]
    if (routes.some((route) => route.dev !== 'lo' || route.gateway !== undefined || route.dst === 'default')) {
      throw new Error('Public-address tests require no external routes or gateways')
    }
  }
}
