#!/usr/bin/env node
import { checkThenConnect } from './adapters/checkThenConnect.js'
import { guardedFetch } from './adapters/guardedFetch.js'
import { requestFilteringAgent, ssrfAgentClient, ssrfReqFilter } from './adapters/libraries.js'
import {
  MissingOptionalPackage,
  missingOptionalPackages,
  type OptionalPackage,
} from './adapters/optional.js'
import { plainFetch } from './adapters/plainFetch.js'
import { vercelGuardedFetch } from './adapters/vercelGuardedFetch.js'
import type { HttpClient } from './adapters/types.js'
import { DIRECT_PROBES, PROBES, type Probe } from './checker/probes.js'
import { LEGEND, renderJson, renderTable } from './checker/report.js'
import { runScan, type ScanResult } from './checker/run.js'
import { startAttackRange } from './range/server.js'

const CLIENTS: Record<string, HttpClient> = {
  plain: plainFetch,
  naive: checkThenConnect,
  guarded: guardedFetch,
  rfa: requestFilteringAgent,
  'ssrf-req-filter': ssrfReqFilter,
  'ssrf-agent': ssrfAgentClient,
  'vercel-guarded': vercelGuardedFetch,
}

/** Clients that compare a package ssrf-lab does not install. */
const REQUIRES: Record<string, readonly OptionalPackage[]> = {
  rfa: ['request-filtering-agent'],
  'ssrf-req-filter': ['ssrf-req-filter'],
  'ssrf-agent': ['ssrf-agent'],
  'vercel-guarded': ['guarded-fetch'],
}

const GROUPS: Record<string, readonly string[]> = {
  all: ['plain', 'naive', 'guarded'],
  libs: ['rfa', 'ssrf-req-filter', 'ssrf-agent'],
}

const SUITES: Record<string, readonly Probe[]> = {
  redirect: PROBES,
  direct: DIRECT_PROBES,
  all: [...PROBES, ...DIRECT_PROBES],
}

const USAGE = `ssrf-lab — run a local attack range against an HTTP client

  ssrf-lab scan [--client <name|all|libs>] [--suite redirect|direct|all]
                [--json] [--fail-on-reach] [--public-address]

  --client         all (the 3 built-in clients), libs (the npm SSRF packages),
                   or one of: ${Object.keys(CLIENTS).join(', ')}
                   libs, rfa, ssrf-req-filter, ssrf-agent and vercel-guarded
                   need the compared package installed beside ssrf-lab; the
                   scan prints the install command when one is missing
  --suite          redirect: attacks that start on the public range (default)
                   direct:   one request at the internal service, in every
                             spelling a URL parser accepts
                   all:      both
  --json           print machine-readable results
  --fail-on-reach  exit 1 when any probe reports REACHED
  --public-address use the isolated entry fixture; requires only lo with
                   93.184.216.34/32 and no external routes (Linux only)
`

async function main(): Promise<void> {
  const argv = process.argv.slice(2)
  if (argv.includes('--help') || argv.includes('-h') || argv[0] === undefined) {
    process.stdout.write(USAGE)
    return
  }

  const json = argv.includes('--json')
  const failOnReach = argv.includes('--fail-on-reach')
  const which = flagValue(argv, '--client') ?? 'all'
  const suiteName = flagValue(argv, '--suite') ?? 'redirect'
  const suite = SUITES[suiteName]
  const names = GROUPS[which] ?? [which]
  const selected = names.map((name) => CLIENTS[name])

  if (suite === undefined) {
    process.stderr.write(`unknown suite: ${suiteName}\n${USAGE}`)
    process.exitCode = 2
    return
  }

  if (selected.some((client) => client === undefined)) {
    process.stderr.write(`unknown client: ${which}\n${USAGE}`)
    process.exitCode = 2
    return
  }

  const missing = await missingOptionalPackages(names.flatMap((name) => REQUIRES[name] ?? []))
  if (missing.length > 0) {
    process.stderr.write(`${new MissingOptionalPackage(missing).message}\n`)
    process.exitCode = 2
    return
  }

  const range = await startAttackRange({ publicAddress: argv.includes('--public-address') })
  const scans: ScanResult[] = []

  try {
    for (const client of selected) {
      if (client === undefined) continue
      scans.push(await runScan(client, range, suite))
    }
  } finally {
    await range.close()
  }

  if (json) {
    process.stdout.write(`${renderJson(scans)}\n`)
  } else {
    process.stdout.write(`${LEGEND}\n`)
    for (const scan of scans) process.stdout.write(`${renderTable(scan)}\n`)
    process.stdout.write('\n')
  }

  if (failOnReach && scans.some((scan) => scan.reached > 0)) process.exitCode = 1
}

function flagValue(argv: readonly string[], flag: string): string | undefined {
  const index = argv.indexOf(flag)
  if (index >= 0) return argv[index + 1]
  const inline = argv.find((entry) => entry.startsWith(`${flag}=`))
  return inline?.slice(flag.length + 1)
}

main().catch((error: unknown) => {
  process.stderr.write(`${String(error)}\n`)
  process.exitCode = 1
})
