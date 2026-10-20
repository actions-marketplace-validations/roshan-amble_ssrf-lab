# Linkwarden application fetch evidence, 2026-10-20

This records a bounded trial of the shared `safeFetch()` function used by
Linkwarden's archive worker and RSS polling. No target source was changed.
The trial does not establish a new vulnerability, maintainer acceptance or
external adoption of ssrf-lab. It has not been proposed upstream.

## Source and provenance

- [Linkwarden source `952ac4540657cae3a67c3ca59433899d2fda8374`](https://github.com/linkwarden/linkwarden/tree/952ac4540657cae3a67c3ca59433899d2fda8374).
- [Verification head `c03503d4857cafdb5002481f9247ff782fe59014`](https://github.com/roshan-amble/ssrf-lab/commit/c03503d4857cafdb5002481f9247ff782fe59014).
- [Successful verification run 39507487611](https://github.com/roshan-amble/ssrf-lab/actions/runs/39507487611).
- Runner merge ref: `82a2fdd0005d7787852b8a4bdeb9c06f33bee316`.
- [Artifact IDs, verified ZIP digests and extracted file digests](provenance.json).
- [Recipe, implementation and reproduction commands](../../../integrations/linkwarden/README.md).

Each artifact ZIP's SHA-256 was checked against GitHub's reported digest before
extracting these files. JSON bytes are unedited. The two source files are
verified against their exact Git blob IDs before TypeScript type erasure and
workspace import resolution. Source/build hashes are retained in each report.

## Measured results

Both jobs installed and built first, then ran in a fresh Linux network
namespace with only loopback enabled. `93.184.216.34/32` was assigned to loopback
as the allowed entry fixture, with no external interfaces or default route.
The range verified containment before importing the application module.

| Runtime | Protected probes | Internal hits | Unsafe application control | Report |
| --- | --- | --- | --- | --- |
| Node 22.23.3 | 9 explicit refusals | 0 | Direct and redirect both reached | [Raw JSON](node22-report.json) |
| Node 24.21.0 | 9 explicit refusals | 0 | Direct and redirect both reached | [Raw JSON](node24-report.json) |

On each runtime:

- Seven direct cases and two redirects produced the application's named address
  or hostname refusal. Each redirect reached the entry fixture once first.
- The protected allowed entry returned HTTP 200 with the expected real body.
  A separate content/allowed-redirect control returned the exact HTML body,
  with two measured content requests and one redirect request.
- Native fetch reached the internal service directly and through a redirect.
- Linkwarden's own private-network opt-out reached through the same two paths.
  The opt-out was confined to negative controls and restored afterward.
- An opted-out request followed by a deliberately thrown policy error remained
  `REACHED`, with one measured internal hit.
- The trial's separate transport dependency audit reported zero advisories.

| Runtime | Source/build identity | Network inventory | Routes | Separate transport audit |
| --- | --- | --- | --- | --- |
| Node 22 | [Source](node22-source.json) | [Interfaces](node22-network.json) | [Routes](node22-routes.json) | [Audit](node22-transport-audit.json) |
| Node 24 | [Source](node24-source.json) | [Interfaces](node24-network.json) | [Routes](node24-routes.json) | [Audit](node24-transport-audit.json) |

The [local Node 24.19.0 smoke report](node24-local-smoke.json) is separate: seven
direct cases plus unsafe/late-error controls passed, with no successful public
entry or redirect coverage claimed for that local mode.

## Scope

The trial transpiles two unchanged application modules and installs a minimal
transport dependency graph with a retained npm lockfile. The three direct
transport versions match the application's pinned Yarn lock. This is not the
full application installation, build or test suite.

`ALLOW_PRIVATE_NETWORK_ACCESS` is off for the protected run and `PROXY` is
unset. The adapter neither injects a resolver nor substitutes fetch. It converts
the real node-fetch v2 response stream to a Web stream and classifies only the
exact upstream address/hostname refusal messages. Upstream DNS lookup errors
share the same error type but are not credited as blocks.

No application boot, RSS job, archive/browser worker, remote Playwright path,
DNS rebinding, proxy, TLS, arbitrary private destination, body limit or credential
forwarding assessment is included. The five-second deadline is a harness limit.
The source remains in Linkwarden's AGPL-3.0 repository; generated modules are
ignored build output and are not vendored into ssrf-lab.

Codex assisted with implementation, testing and documentation.
