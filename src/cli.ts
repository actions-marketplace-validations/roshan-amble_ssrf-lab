#!/usr/bin/env node
import { checkThenConnect } from './adapters/checkThenConnect.js'
import { guardedFetch } from './adapters/guardedFetch.js'
import { plainFetch } from './adapters/plainFetch.js'
import type { HttpClient } from './adapters/types.js'
import { LEGEND, renderJson, renderTable } from './checker/report.js'
import { runScan, type ScanResult } from './checker/run.js'
import { startAttackRange } from './range/server.js'

const CLIENTS: Record<string, HttpClient> = {
  plain: plainFetch,
  naive: checkThenConnect,
  guarded: guardedFetch,
}

const USAGE = `ssrf-lab — run a local attack range against an HTTP client

  ssrf-lab scan [--client plain|naive|guarded|all] [--json] [--fail-on-reach]

  --client         which client to scan (default: all)
  --json           print machine-readable results
  --fail-on-reach  exit 1 when any probe reports REACHED
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
  const selected = which === 'all' ? Object.values(CLIENTS) : [CLIENTS[which]]

  if (selected[0] === undefined) {
    process.stderr.write(`unknown client: ${which}\n${USAGE}`)
    process.exitCode = 2
    return
  }

  const range = await startAttackRange()
  const scans: ScanResult[] = []

  try {
    for (const client of selected) {
      if (client === undefined) continue
      scans.push(await runScan(client, range))
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
