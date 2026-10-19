# guarded-fetch source-build CI integration

This is a candidate CI contribution for
[vercel-labs/guarded-fetch](https://github.com/vercel-labs/guarded-fetch), built
and verified separately before proposing it upstream. A proposal or a test in
our fork is not evidence that the maintainers have adopted ssrf-lab.

[Recorded Node 22 and 24 evidence](../../docs/evidence/2026-10-19-guarded-fetch-source/README.md):
each run explicitly blocked 9/9 cases with zero internal hits, completed the
allowed-entry request, and observed both unsafe controls reaching the fixture.

## Pinned source

- Upstream base: `25e89f08d988c1be0eef8ee0e3dbe69d725e60d3`, version 0.1.6.
- Candidate: [`d584d58e61cb9e437a1e0fd9e7df2698c7c3eba7`](https://github.com/roshan-amble/guarded-fetch/commit/d584d58e61cb9e437a1e0fd9e7df2698c7c3eba7).
- Harness Action: `ac0d4906592a5c41c27785b7a4327d449bc10da9`.
- [Verification workflow](../../.github/workflows/guarded-fetch-source.yml).

The candidate adds a 31-line module that imports `../dist/index.mjs`, plus two
steps in the existing CI job. The existing same-repository PR condition and
read-only token permissions are preserved. The module creates and closes a
normal guarded dispatcher, without an address allowlist, injected resolver,
replacement fetch function, or policy bypass. Only the library's typed
`HOSTNAME_UNSAFE` and `REDIRECT_TO_UNSAFE_HOST` refusals are mapped to an address
block; the selected destinations are literals or the explicitly blocked
`localhost` name, so these cases do not depend on external DNS.

## Coverage

The Action runs seven direct-address cases and two redirects inside a fresh
Linux network namespace. The successful-entry control must complete, and two
unsafe-fetch controls must reach the internal fixture. Independent entry and
internal request counters are retained per probe. A measured internal hit
cannot become a passing result because the client later throws.

This bounded check excludes DNS rebinding, TLS, cross-origin credentials,
arbitrary private destinations, body limits, and deadlines as target policy.
The separate pinned npm 0.1.5 comparison has broader probes and remains
documented in [INTEGRATIONS.md](../../docs/INTEGRATIONS.md).

## Reproduce

Use a disposable Linux environment with Node 22.19+ or 24 and pnpm 10.32.1.
From a checkout of ssrf-lab:

```bash
npm ci --ignore-scripts
npm run build
git clone https://github.com/roshan-amble/guarded-fetch.git consumer
git -C consumer checkout --detach d584d58e61cb9e437a1e0fd9e7df2698c7c3eba7
(cd consumer && pnpm install --frozen-lockfile --ignore-scripts && pnpm build && pnpm validate)
```

With network namespace support, run the isolated check:

```bash
sudo env "PATH=$PATH" unshare --net -- bash -euo pipefail -c '
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  node examples/custom-fetcher/check.mjs --isolated \
    --module consumer/scripts/ssrf-lab-fetcher.mjs --json
'
```

Without namespace support, a limited local smoke check exercises only seven
direct-address cases and the direct unsafe control:

```bash
node examples/custom-fetcher/check.mjs \
  --module consumer/scripts/ssrf-lab-fetcher.mjs --json
```

The full verification runs on Node 22 and 24, validates all 237 upstream tests,
formatting, lint, type checking and build, and uploads reports even for a
failed isolated check. Check the workflow conclusion before treating an
artifact as passing evidence.

Codex assisted with implementation, testing and documentation.
