import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

export function validateIntegrationAudit(report, lock, reviewed) {
  assert(report && !report.error && report.metadata && report.vulnerabilities, 'Invalid audit response')
  const entries = Object.entries(report.vulnerabilities)
  assert.equal(report.metadata.vulnerabilities.total, entries.length, 'Audit total mismatch')
  // A version change requires a new review, even if the advisory disappears.
  for (const [path, version] of Object.entries(reviewed.versions)) {
    assert.equal(lock.packages[path]?.version, version, `Research dependency changed: ${path}`)
  }
  for (const [name, finding] of entries) {
    const allowed = reviewed.findings[name]
    assert(allowed, `Unreviewed package: ${name}`)
    assert.equal(finding.name, name)
    assert.equal(finding.severity, allowed.severity, `Severity changed: ${name}`)
    assert.deepEqual([...finding.nodes].sort(), [...allowed.nodes].sort(), `Dependency paths changed: ${name}`)
    const via = finding.via.map(item => typeof item === 'string' ? item : `${item.url}|${item.range}|${item.severity}`).sort()
    for (const item of via) assert(allowed.via.includes(item), `Unreviewed advisory: ${name}: ${item}`)
  }
  return entries.length
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = JSON.parse(readFileSync(process.argv[2], 'utf8'))
  const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url), 'utf8'))
  const reviewed = JSON.parse(readFileSync(new URL('./reviewed-audit.json', import.meta.url), 'utf8'))
  const count = validateIntegrationAudit(report, lock, reviewed)
  console.log(`n8n research-fixture audit reviewed: ${count} known package findings; not a zero-vulnerability audit.`)
}
