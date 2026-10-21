import { readFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DIRECT_PROBES } from '../checker/probes.js'
import { runScan } from '../checker/run.js'
import { startAttackRange, type AttackRange } from '../range/server.js'
import {
  installHint,
  isMissing,
  loadOptional,
  MissingOptionalPackage,
  missingOptionalPackages,
  OPTIONAL_PACKAGES,
} from './optional.js'
import type { HttpClient } from './types.js'

const manifest = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as {
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
}

function notFound(name: string): Error {
  return Object.assign(new Error(`Cannot find package '${name}' imported from /x/dist/adapters/libraries.js`), {
    code: 'ERR_MODULE_NOT_FOUND',
  })
}

describe('compared packages', () => {
  it('are pinned devDependencies with the versions the install hint names', () => {
    for (const [name, version] of Object.entries(OPTIONAL_PACKAGES)) {
      expect(manifest.devDependencies?.[name]).toBe(version)
    }
  })

  it('are never runtime dependencies, so installing ssrf-lab installs none of them', () => {
    for (const name of Object.keys(OPTIONAL_PACKAGES)) {
      expect(manifest.dependencies?.[name]).toBeUndefined()
    }
  })

  it('are all loadable in this repository', async () => {
    const names = Object.keys(OPTIONAL_PACKAGES) as (keyof typeof OPTIONAL_PACKAGES)[]
    expect(await missingOptionalPackages(names)).toEqual([])
  })
})

describe('a missing compared package', () => {
  it('is recognized only when the package itself is not found', () => {
    expect(isMissing(notFound('ssrf-agent'), 'ssrf-agent')).toBe(true)
    // A dependency OF the package is missing: that is a broken install, not an
    // uninstalled optional package, and must surface as the real error.
    expect(isMissing(notFound('ip'), 'ssrf-agent')).toBe(false)
    expect(isMissing(new Error("Cannot find package 'ssrf-agent'"), 'ssrf-agent')).toBe(false)
  })

  it('becomes an install hint with exact versions for npm and npx', async () => {
    await expect(
      loadOptional('ssrf-agent', () => Promise.reject(notFound('ssrf-agent'))),
    ).rejects.toThrow(MissingOptionalPackage)

    const hint = installHint(['ssrf-agent', 'guarded-fetch'])
    expect(hint).toContain('npm install --save-dev ssrf-agent@1.0.5 guarded-fetch@0.1.5')
    expect(hint).toContain('npx -p ssrf-lab -p ssrf-agent@1.0.5 -p guarded-fetch@0.1.5 ssrf-lab scan')
  })

  it('passes any other load failure through unchanged', async () => {
    const broken = new SyntaxError('Unexpected token')
    await expect(loadOptional('ssrf-agent', () => Promise.reject(broken))).rejects.toBe(broken)
  })
})

describe('the checker and a client that never ran', () => {
  let range: AttackRange
  beforeAll(async () => { range = await startAttackRange() })
  afterAll(async () => { await range.close() })

  it('ends the scan instead of scoring a request that was never made', async () => {
    const absent: HttpClient = {
      name: 'absent',
      supportsConnectHook: false,
      fetch: () => Promise.reject(new MissingOptionalPackage(['ssrf-agent'])),
    }
    await expect(runScan(absent, range, DIRECT_PROBES)).rejects.toThrow(MissingOptionalPackage)
  })
})
