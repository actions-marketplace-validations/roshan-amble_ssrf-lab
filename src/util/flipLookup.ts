import type { LookupFunction } from 'node:net'

/**
 * A resolver that changes its answer between calls.
 *
 * This is DNS rebinding compressed into one process: the first answer is the
 * one a pre-check sees, and every later answer is the one a socket gets. A
 * real attacker achieves the same effect with a TTL of 0 and a name they own.
 *
 * The rebinding here is SIMULATED. It proves whether a client judges the
 * address it connects to. It does not prove anything about a real resolver.
 */
export function flipLookup(answers: readonly string[]): LookupFunction {
  let call = 0

  return ((_hostname: string, options: unknown, callback: unknown) => {
    const done = (typeof options === 'function' ? options : callback) as (
      error: NodeJS.ErrnoException | null,
      address?: string | { address: string; family: number }[],
      family?: number,
    ) => void

    const index = Math.min(call, answers.length - 1)
    call += 1
    const address = answers[index] ?? '127.0.0.1'
    const family = address.includes(':') ? 6 : 4

    const wantsAll = typeof options === 'object' && options !== null && 'all' in options
      ? Boolean((options as { all?: boolean }).all)
      : false

    if (wantsAll) done(null, [{ address, family }])
    else done(null, address, family)
  }) as LookupFunction
}
