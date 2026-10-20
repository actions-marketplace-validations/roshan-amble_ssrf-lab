import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { Readable } from 'node:stream'

export const sourceInfo = JSON.parse(readFileSync(new URL('./dist/source.json', import.meta.url), 'utf8'))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
assert.equal(sourceInfo.sourceCommit, '952ac4540657cae3a67c3ca59433899d2fda8374')
for (const [file, hashes] of Object.entries(sourceInfo.sourceFiles)) {
  assert.equal(sha256(readFileSync(new URL(`./dist/${file}`, import.meta.url))), hashes.emittedSha256)
}
assert.equal(sha256(readFileSync(new URL('./package-lock.json', import.meta.url))), sourceInfo.trialLockSha256)
const require = createRequire(import.meta.url)
for (const [name, version] of Object.entries(sourceInfo.transportDependencies)) {
  assert.equal(require(`${name}/package.json`).version, version)
}
const { safeFetch } = await import('./dist/safeFetch.js')
const { UnsafeUrlError } = await import('./dist/ssrf.js')

export function createFetcher({ unsafeControl = false, lateErrorControl = false } = {}) {
  return {
    name: lateErrorControl ? 'Linkwarden opt-out, then policy error' : unsafeControl ? 'Linkwarden opt-out control' : 'Linkwarden application safeFetch()',
    async fetchUrl(url, { signal }) {
      assert.equal(process.env.ALLOW_PRIVATE_NETWORK_ACCESS === 'true', unsafeControl,
        'Unexpected application policy: private-network opt-out is only permitted for the negative control')
      assert(!process.env.PROXY, 'This trial requires the application proxy setting to be unset')
      const response = await safeFetch(url, { signal })
      if (lateErrorControl) {
        await response.buffer()
        throw new UnsafeUrlError('URL resolves to a blocked internal IP address.')
      }
      // Preserve the real response and body bytes. node-fetch v2 exposes a
      // Node stream; the onboarding adapter consumes a Web ReadableStream.
      return new Response(response.body ? Readable.toWeb(response.body) : null, {
        status: response.status, statusText: response.statusText, headers: response.headers.raw(),
      })
    },
    classifyRefusal(error) {
      if (error instanceof UnsafeUrlError && [
        'URL resolves to a blocked internal IP address.',
        'URL resolves to a blocked internal hostname.',
      ].includes(error.message)) return 'forbidden-address'
      // The application also wraps DNS failures in UnsafeUrlError. Those
      // messages must remain unexplained prevention, not an address block.
      return undefined
    },
  }
}

export const { name, fetchUrl, classifyRefusal } = createFetcher()
