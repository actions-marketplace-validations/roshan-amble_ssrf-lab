import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const here = dirname(fileURLToPath(import.meta.url))
const source = resolve(process.argv[2] ?? '')
const sourceCommit = '952ac4540657cae3a67c3ca59433899d2fda8374'
const files = {
  'packages/lib/safeFetch.ts': 'fc659a0dabbce782b4c93b62ef9208f0a10fbd0c',
  'packages/lib/ssrf.ts': 'a27013b39dcafe39b2cbe2ebc17be3d5b48729f8',
}
const sha256 = content => createHash('sha256').update(content).digest('hex')
assert(process.argv[2], 'Pass the path to a pinned Linkwarden checkout')
assert.equal(execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), sourceCommit)
const metadataFiles = ['package.json', 'apps/web/package.json', 'yarn.lock']
execFileSync('git', ['-C', source, 'diff', '--quiet', 'HEAD', '--', ...Object.keys(files), ...metadataFiles])
const manifest = JSON.parse(readFileSync(resolve(source, 'apps/web/package.json'), 'utf8'))
const transport = JSON.parse(readFileSync(resolve(here, 'package.json'), 'utf8')).dependencies
const yarnLock = readFileSync(resolve(source, 'yarn.lock'), 'utf8')
for (const [name, version] of Object.entries(transport)) {
  const descriptor = `${name}@npm:${manifest.dependencies[name]}`
  const blocks = yarnLock.split(/\n\s*\n/).filter(block => block.split('\n')[0].includes(descriptor))
  assert.equal(blocks.length, 1, `Expected one upstream lock entry for ${descriptor}`)
  assert.equal(blocks[0].match(/\n  version: (\S+)/)?.[1], version, `${name}: upstream version differs`)
}
const output = resolve(here, 'dist')
mkdirSync(output, { recursive: true })
const hashes = {}
for (const [path, blob] of Object.entries(files)) {
  const bytes = readFileSync(resolve(source, path))
  const gitHash = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
  assert.equal(gitHash, blob, `${path}: source differs from the pinned Git blob`)
  const result = ts.transpileModule(bytes.toString('utf8'), {
    fileName: path,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
    reportDiagnostics: true,
  })
  assert(!result.diagnostics?.some(row => row.category === ts.DiagnosticCategory.Error), 'TypeScript transpilation failed')
  let code = result.outputText
  if (path.endsWith('safeFetch.ts')) {
    // Resolve the workspace import to the same, unchanged compiled guard.
    assert.equal(code.split('"@linkwarden/lib/ssrf"').length - 1, 1)
    code = code.replace('"@linkwarden/lib/ssrf"', '"./ssrf.js"')
  }
  const name = path.split('/').at(-1).replace(/\.ts$/, '.js')
  writeFileSync(resolve(output, name), code)
  hashes[name] = { gitBlob: blob, sourceSha256: sha256(bytes), emittedSha256: sha256(code) }
}
const info = {
  repository: 'linkwarden/linkwarden', sourceCommit, applicationVersion: manifest.version,
  api: 'packages/lib/safeFetch.ts safeFetch()',
  sourceFiles: hashes, typescript: ts.version, transportDependencies: transport,
  upstreamLockSha256: sha256(yarnLock),
  trialLockSha256: sha256(readFileSync(resolve(here, 'package-lock.json'))),
  build: 'TypeScript type erasure and workspace import resolution; no policy or transport replacements',
  scope: 'Two unchanged application modules with an isolated dependency installation, not a full application build',
}
writeFileSync(resolve(output, 'source.json'), JSON.stringify(info, null, 2) + '\n')
console.log(JSON.stringify(info, null, 2))
