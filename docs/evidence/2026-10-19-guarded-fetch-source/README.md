# guarded-fetch source-build regression evidence

These are the unedited JSON reports downloaded from
[verification run 39279891528](https://github.com/roshan-amble/ssrf-lab/actions/runs/39279891528).
They exercise the proposed consumer module against the built guarded-fetch
0.1.6 checkout. This is a test of a candidate contribution, not a claim of
maintainer acceptance or external adoption.

| Runtime | Explicit blocks | Internal hits | Allowed entry | Unsafe controls | Raw report |
| --- | --- | --- | --- | --- | --- |
| Node 22.23.3 | 9/9 | 0 | HTTP 200, 1 hit | 2/2 reached | [node22.json](node22.json) |
| Node 24.21.0 | 9/9 | 0 | HTTP 200, 1 hit | 2/2 reached | [node24.json](node24.json) |

Both reports record gate exit 0. The consumer's existing 237 tests, build,
formatting, lint, and type checking run before the regression Action. The
workflow's assertions require nine explicit blocks, no internal hits, a
successful allowed-entry request, and two measured unsafe controls before
copying either report into the verification artifact.

## Source and provenance

- Harness PR head: `cb9f9ac409b8be76f795911d0c202568b9a360d6`.
- GitHub PR merge ref used by the runner: `ee63202bd6977ee7a5281e71c33560d699243cae`.
- Upstream base: `25e89f08d988c1be0eef8ee0e3dbe69d725e60d3`.
- Consumer candidate: `d584d58e61cb9e437a1e0fd9e7df2698c7c3eba7`.
- Harness Action: `ac0d4906592a5c41c27785b7a4327d449bc10da9`.
- Node 22 artifact: `12200880100`; ZIP SHA-256
  `f86ad8432dc071086a54578a4810201c21bc37392972b4a6afec68cceda4aa67`.
- Node 24 artifact: `12199773038`; ZIP SHA-256
  `259697634a50d26925d03484880ff9f706a961f2695f4109663347c7aa3953c4`.

Each downloaded artifact digest was verified, and each artifact's
`consumer-commit.txt` matched the candidate commit above. The raw reports are
retained here because workflow artifacts expire after 30 days.

Scope is seven direct-address cases and two redirects using literal addresses
and localhost. It excludes DNS rebinding, TLS, cross-origin credentials,
arbitrary private destinations, response-body limits, and target deadlines.
The [integration notes](../../../integrations/guarded-fetch/README.md) explain
the adapter and reproduction steps.
