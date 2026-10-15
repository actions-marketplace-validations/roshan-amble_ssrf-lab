import { createGuardedDispatcher, guardedFetch, GuardedFetchError } from 'guarded-fetch'

// Replace this module with an import of YOUR application's existing fetcher.
// This runnable example uses the pinned guarded-fetch package, without a lab
// allowlist or a replacement address/redirect policy in the test adapter.
const dispatcher = createGuardedDispatcher()
export const name = 'example application using guarded-fetch 0.1.5'

export function fetchUrl(url, { signal, timeoutMs }) {
  return guardedFetch(url, { signal, timeoutMs, dispatcher, opaqueErrors: true })
}

// Only identify explicit refusals from the implementation being tested.
// Connection errors, aborts, DNS failures and arbitrary 4xx responses do not
// establish that an SSRF policy rejected a destination.
export function classifyRefusal(error) {
  if (!(error instanceof GuardedFetchError)) return undefined
  if (['hostname_unsafe', 'host_not_allowed', 'redirect_to_unsafe_host'].includes(error.code)) {
    return 'forbidden-address'
  }
  return undefined
}

export async function close() {
  await dispatcher.destroy()
}
