# Linkwarden application fetch trial

This trial calls the same `safeFetch()` used by Linkwarden's archive worker and
RSS polling. It exercises two unchanged application modules from
[`952ac4540657cae3a67c3ca59433899d2fda8374`](https://github.com/linkwarden/linkwarden/tree/952ac4540657cae3a67c3ca59433899d2fda8374):
`packages/lib/safeFetch.ts` and `packages/lib/ssrf.ts`. The web manifest at that
revision reports `v2.16.3`. This is a source revision trial, not a release claim.

The existing upstream `ssrf.test.ts` checks address classification and uses an
injected DNS lookup for hostname policy cases. This adds measured requests
through the real `safeFetch()` HTTP transport and redirect loop. It does not
replace those unit tests or claim a new vulnerability.

## What runs

The [build script](build-source.mjs) verifies the Git revision, unchanged files,
and exact Git blob hashes before transpiling the two TypeScript modules. The
only import rewrite resolves the workspace guard alias to that same compiled
guard. The three direct transport dependencies match the upstream Yarn lock:
`node-fetch@2.7.0`, `https-proxy-agent@7.0.6` and `socks-proxy-agent@8.0.2`.
They use a separate, retained npm lockfile; this does not reproduce the entire
application's Yarn dependency graph or run its full build/test suite.

The [fetcher module](fetcher.mjs) imports that source, preserves its normal
address policy and default redirect limit, and attaches the harness's abort
signal. Its response adapter converts the real Node response stream to a Web
ReadableStream without inventing response bodies or success results. Only the
upstream typed error with the exact internal-address or internal-hostname
refusal message is classified as an address block. Upstream wraps DNS failures
in the same error type; those messages are deliberately not classified as blocks.

The [verification workflow](../../.github/workflows/linkwarden-source.yml) runs
on Node 22 and 24, with only loopback enabled in a fresh network namespace. The
public-shaped entry address is assigned to loopback within that namespace.
The range refuses to start if containment is missing. The selected checks are:

- Seven direct address cases and two redirects, with entry/internal counters.
- Successful allowed entry, content fetch and allowed redirect with real bodies.
- Native fetch and Linkwarden's own private-network opt-out must reach the
  internal fixture directly and through a redirect.
- A policy error deliberately thrown after an opted-out request must remain
  `REACHED` because the target counter recorded it.

The protected run requires `ALLOW_PRIVATE_NETWORK_ACCESS` to be disabled and
`PROXY` to be unset. The opt-out is enabled only for the measured negative
controls and is restored afterward. No alternate resolver or fetch function
is injected into the application modules.

## Reproduce

From a checkout of ssrf-lab with Node 22.12+ or 24:

```bash
npm ci --ignore-scripts
npm ci --ignore-scripts --prefix integrations/linkwarden
npm run build
git clone https://github.com/linkwarden/linkwarden.git consumer
git -C consumer checkout --detach 952ac4540657cae3a67c3ca59433899d2fda8374
node integrations/linkwarden/build-source.mjs consumer
node integrations/linkwarden/verify.mjs --direct-only
```

The last command is a seven-case local smoke check. To exercise the successful
entry and redirects, use a disposable Linux runner with namespace support:

```bash
sudo env "PATH=$PATH" unshare --net -- bash -euo pipefail -c '
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  node integrations/linkwarden/verify.mjs
'
```

Exit 0 means every selected probe had an explicit policy refusal and zero
internal hits, with required controls passing. Exit 1 means measured internal
reach. Exit 2 means setup, controls or coverage were inconclusive. The full CI
run retains raw reports, source/build hashes, network inventory and the separate
transport dependency audit, including when a job fails.

[Recorded Node 22.23.3 and 24.21.0 evidence](../../docs/evidence/2026-10-20-linkwarden/README.md)
passed all nine address/redirect cases with zero internal hits. Both runtimes
completed the allowed entry/content/redirect controls, measured two reaches
through native fetch and two through the application's opt-out, and detected
the late-error reach. Local Node 24.19.0 separately passed the seven direct
cases and controls. The evidence retains the raw JSON and verified ZIP digests.

## Scope and status

This tests the shared HTTP fetch function used by application code. It does
not boot Linkwarden, run an RSS job or a browser archive, or cover its remote
Playwright path, DNS rebinding, proxies, TLS, arbitrary private ranges, body
limits or credential forwarding. Its five-second deadline is a harness limit,
not a claim about application timeout policy.

The target source remains in its own AGPL-3.0 repository; generated modules are
ignored build output and are not vendored here. The trial supports
[Linkwarden's test-coverage proposal #1869](https://github.com/linkwarden/linkwarden/issues/1869),
which awaits maintainer feedback. It does not establish maintainer acceptance
or external adoption of ssrf-lab.

Codex assisted with implementation, testing and documentation.
