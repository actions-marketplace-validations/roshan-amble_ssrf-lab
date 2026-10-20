# Dependencies and the deliberately vulnerable fixture

This repository is a local research harness, not an SSRF protection service.
The default comparison intentionally includes a vulnerable version of a package.
Do not deploy this checkout as a production fetch service or expose its test tools.

## Development toolchain

The test runner was upgraded from Vitest 2.1.9 to 5.0.3 and the lockfile regenerated
without `--force` or `--legacy-peer-deps`. Other direct dependencies were pinned to
their previously resolved versions. CI runs on Node.js 22 and 24. Use Node 22.12.0
or newer on a release line supported by Vitest 5.

## Research versions must remain reproducible

| Package | Pinned version | Role |
| --- | --- | --- |
| request-filtering-agent | 3.2.1 | Comparison target |
| ssrf-req-filter | 1.1.1 | Comparison target |
| ssrf-agent | 1.0.5 | Vulnerable research target |
| ip | 1.1.9 | Transitive dependency of ssrf-agent |
| ipaddr.js | 2.5.0 | Transitive dependency of the comparison targets |
| guarded-fetch | 0.1.5 | Additional comparison target |

The dependency-upgrade verification compared each of these packages' versions,
resolved tarball URLs, and integrity hashes against the original lockfile.
No research dependency was silently replaced to obtain a green audit.

## Two package findings, one documented exception

At upgrade verification, `npm audit` reported two high-severity package entries:
`ip` and its dependent `ssrf-agent`. The underlying advisory is
[GHSA-2p57-rm9w-gvfp](https://github.com/advisories/GHSA-2p57-rm9w-gvfp).
Those audit entries are separate from the project's pending CVE request. They do
not establish assignment, novelty, or severity of that request.

`scripts/check-audit.mjs` allows only this advisory on the exact fixture versions.
It fails on an additional package, changed fixture version, new advisory on an
excepted package, malformed report, or inconsistent totals. Seven tests exercise
that gate. A passing gate means **no unreviewed findings**, not zero vulnerabilities.

Run the checks with:

```bash
mkdir -p verification
node --test scripts/check-audit.test.mjs
npm audit --json > verification/dependency-audit.json
node scripts/check-audit.mjs
```

`npm audit` currently exits 1 for the known fixture; the subsequent gate separately
evaluates the report. Never disable the audit or allow all advisories on a package
just because it is part of a security lab.

## Separate n8n research fixture

The optional n8n integration has its own lockfile and audit gate under
`integrations/n8n/`. It pins `@n8n/backend-network@1.17.3` and
`@n8n/config@2.41.2`, matching the components in n8n 2.43.5. Its reviewed audit
snapshot contains eight vulnerable package entries: `@n8n/api-types`,
`@n8n/backend-common`, `@n8n/backend-network`, `@n8n/decorators`, `axios`,
`n8n-workflow`, `qs`, and `stream-json`. These include transitive impact entries,
not eight new discoveries.

`integrations/n8n/reviewed-audit.json` records exact advisory URLs, affected
ranges, severities, install paths, and pinned versions. The separate gate
rejects new advisories, package entries, paths, or versions, and permits removal
of reviewed advisories. Five tests cover that gate. The fixture is kept intact
for reproducibility and exercised only as a local research client. Do not
interpret the exception as a production dependency recommendation.

```bash
node --test integrations/n8n/check-audit.test.mjs
npm audit --prefix integrations/n8n --json > verification/n8n-audit.json
node integrations/n8n/check-audit.mjs verification/n8n-audit.json
```

## Isolation

The optional [Linkwarden source trial](../integrations/linkwarden/README.md)
uses another separate npm lockfile. Its three direct transport dependency
versions match the pinned application's Yarn lock; the rest of the application
dependency graph is not installed. The recorded 2026-10-20 Node 22/24 transport
audits reported zero advisories and are retained with the request evidence.
The workflow fails on any advisory instead of introducing an audit exception.

CI installs dependencies before creating a network namespace, then runs the tests,
scans, and demonstration with only loopback enabled. There is no fallback to an
unrestricted network. The verification workflow has only repository read access;
it does not publish packages, create releases, or modify repository content.
The new integration job assigns a public-shaped entry address to `lo` inside
that namespace, with no external interfaces or routes. See
[integration reproduction](INTEGRATIONS.md) for its fail-closed checks.
