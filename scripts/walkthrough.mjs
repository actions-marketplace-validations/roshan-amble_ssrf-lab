import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { setTimeout as pause } from 'node:timers/promises'

const prefix = process.argv[2] || 'verification/walkthrough'
const page = title => process.stdout.write(`\x1b[2J\x1b[Hssrf-lab | ${title}\n${'='.repeat(87)}\n\n`)
const run = async (label, unsafe) => {
  page(label)
  const args = ['examples/custom-fetcher/check.mjs', '--isolated', ...(unsafe ? ['--unsafe'] : []), '--json']
  console.log(`$ node ${args.join(' ')}`)
  console.log('\nRunning real requests inside the isolated fixture...\n')
  const result = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 120000 })
  if (result.error) throw result.error
  assert.equal(result.status, unsafe ? 1 : 0, result.stderr)
  const report = JSON.parse(result.stdout)
  writeFileSync(`${prefix}-${unsafe ? 'unsafe' : 'protected'}.json`, result.stdout)
  assert.equal(report.scan.results.length, 9)
  assert.equal(report.negativeControl.reached, 2)
  assert(report.scan.positiveControl.publicHits > 0)
  console.log('PROBE                           RESULT      INTERNAL HITS')
  for (const row of report.scan.results) {
    console.log(`${row.probeId.padEnd(31)} ${row.verdict.padEnd(11)} ${row.internalHits}`)
    await pause(200)
  }
  console.log(`\nAllowed entry: HTTP ${report.scan.positiveControl.status}; measured hits: ${report.scan.positiveControl.publicHits}`)
  console.log('Native-fetch controls: 2/2 reached, as required.')
  console.log(`Gate exit: ${result.status} | ${unsafe ? 'CI fails: internal requests arrived.' : 'CI passes: all nine cases explicitly refused.'}`)
  console.log('\nTable rendered from this command\'s captured JSON. Raw reports are saved.')
  await pause(11000)
  return report
}
page('A failed request does not prove SSRF protection')
console.log('This is a recorded execution, with pauses for reading.\n')
console.log('1. Native fetch: the internal service receives the requests.')
console.log('2. The included guarded-fetch example: explicit policy refusals.')
console.log('3. The exit status becomes the CI gate.\n')
console.log('Environment: GitHub Ubuntu runner, loopback-only network namespace.')
console.log(`Node: ${process.version}`)
console.log('Scope: seven direct-address cases + two redirects. No DNS rebinding or TLS.')
await pause(6500)
const unsafe = await run('1 / 2 | Deliberately unsafe control', true)
const protectedReport = await run('2 / 2 | Example application using guarded-fetch 0.1.5', false)
page('Use your application\'s actual fetcher')
console.log('The same checker drives the reusable GitHub Action.\n')
console.log(`Captured unsafe run:    ${unsafe.scan.reached}/9 reached, exit ${unsafe.exitCode}`)
console.log(`Captured protected run: ${protectedReport.scan.blocked}/9 blocked, exit ${protectedReport.exitCode}\n`)
console.log('Connect your existing fetch function and its real policy errors.')
console.log('Keep the successful-entry and unsafe-client controls.\n')
console.log('Get the tutorial, code, raw reports and recording:')
console.log('github.com/roshan-amble/ssrf-lab\n')
console.log('Bounded regression coverage. Not a security certification.')
await pause(14000)
