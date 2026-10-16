import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(process.env.SSRF_LAB_ROOT || join(dirname(fileURLToPath(import.meta.url)), '..'))
const reports = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), 'ssrf-lab-'))
const reportPath = join(reports, 'report.json')
const errorsPath = join(reports, 'errors.txt')
const output = (name, value) => {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`)
}
output('report-path', reportPath)
output('errors-path', errorsPath)
let status = 2
try {
  if (process.platform !== 'linux') throw new Error('Use a disposable GitHub-hosted Ubuntu runner')
  const [major, minor] = process.versions.node.split('.').map(Number)
  if (major < 22 || (major === 22 && minor < 19)) throw new Error('Use Node.js 22.19+ or 24+')
  const workspace = resolve(process.env.GITHUB_WORKSPACE || process.cwd())
  const cwd = resolve(workspace, process.env.SSRF_LAB_WORKDIR || '.')
  const moduleInput = process.env.SSRF_LAB_MODULE
  if (!moduleInput || /[\r\n]/.test(moduleInput)) throw new Error('Set fetcher-module to a module path')
  const modulePath = isAbsolute(moduleInput) ? moduleInput : resolve(cwd, moduleInput)
  if (!existsSync(modulePath)) throw new Error(`Fetcher module does not exist: ${modulePath}`)
  // All user inputs are positional argv values, never shell source. The
  // namespace is verified by check.mjs before it imports application code.
  const child = spawnSync('sudo', ['-n', 'env', `PATH=${process.env.PATH}`, 'unshare', '--net', '--',
    'bash', '-euo', 'pipefail', '-c',
    'ip link set lo up; ip address add 93.184.216.34/32 dev lo; exec "$1" "$2" --module "$3" --isolated --json',
    'ssrf-lab', process.execPath, join(root, 'examples/custom-fetcher/check.mjs'), modulePath],
  { cwd, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024 })
  writeFileSync(reportPath, child.stdout || '')
  writeFileSync(errorsPath, (child.stderr || '') + (child.error ? `${child.error.message}\n` : ''))
  if (child.error || ![0, 1, 2].includes(child.status)) throw new Error('Isolated check did not complete; inspect errors-path')
  // Never turn a broken setup into a passing action.
  if (!child.stdout?.trim()) throw new Error('No report was produced; inspect errors-path')
  const report = JSON.parse(child.stdout)
  if (report.mode !== 'isolated-address-and-redirect' || report.exitCode !== child.status ||
      report.scan?.results?.length !== 9 || report.negativeControl?.reached !== 2 ||
      !(report.scan?.positiveControl?.publicHits > 0)) throw new Error('Incomplete isolated report')
  status = child.status
  const hits = report.scan.results.reduce((n, row) => n + row.internalHits, 0)
  const summary = `SSRF Lab: ${report.scan.blocked}/9 blocked; ${report.scan.reached}/9 reached; ${hits} internal hits; exit ${status}.`
  console.log(summary)
  console.log(`JSON report: ${reportPath}`)
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
    `### SSRF Lab regression check\n\n${summary}\n\nAllowed entry: HTTP ${report.scan.positiveControl.status}. Native-fetch controls: 2/2 reached.\n\nScope: seven direct-address cases and two redirects. DNS rebinding and TLS are not covered.\n`)
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  appendFileSync(errorsPath, `${message}\n`)
  if (!existsSync(reportPath) || !readFileSync(reportPath, 'utf8').trim()) {
    writeFileSync(reportPath, JSON.stringify({ exitCode: 2, error: message }, null, 2) + '\n')
  }
  console.error(message)
  status = 2
} finally {
  output('exit-code', status)
  process.exitCode = status
}
