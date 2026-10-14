import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { validateIntegrationAudit } from './check-audit.mjs'

const reviewed = JSON.parse(readFileSync(new URL('./reviewed-audit.json', import.meta.url)))
const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)))
const finding = { name: 'qs', severity: reviewed.findings.qs.severity, nodes: reviewed.findings.qs.nodes, via: [] }
const report = { metadata: { vulnerabilities: { total: 1 } }, vulnerabilities: { qs: finding } }
test('accepts removal of known advisories without expanding the exception', () => {
  assert.equal(validateIntegrationAudit(report, lock, reviewed), 1)
})
test('rejects an additional advisory on a reviewed package', () => {
  const changed = structuredClone(report)
  changed.vulnerabilities.qs.via.push({ url: 'https://example.invalid/new', range: '*', severity: 'moderate' })
  assert.throws(() => validateIntegrationAudit(changed, lock, reviewed), /Unreviewed advisory/)
})
test('rejects a changed dependency version', () => {
  const changed = structuredClone(lock)
  changed.packages['node_modules/qs'].version = '0.0.0'
  assert.throws(() => validateIntegrationAudit(report, changed, reviewed), /Research dependency changed/)
})
test('rejects a new vulnerable package', () => {
  const changed = structuredClone(report)
  changed.vulnerabilities.other = { ...finding, name: 'other' }
  changed.metadata.vulnerabilities.total = 2
  assert.throws(() => validateIntegrationAudit(changed, lock, reviewed), /Unreviewed package/)
})
test('rejects malformed and incomplete audit responses', () => {
  assert.throws(() => validateIntegrationAudit({ error: 'network' }, lock, reviewed))
  const changed = structuredClone(report)
  changed.metadata.vulnerabilities.total = 0
  assert.throws(() => validateIntegrationAudit(changed, lock, reviewed), /Audit total mismatch/)
})
