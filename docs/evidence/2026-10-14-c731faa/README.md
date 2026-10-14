# Pinned integration evidence, 2026-10-14

These are unedited files from the two integration artifacts in
[CI run 38620982627](https://github.com/roshan-amble/ssrf-lab/actions/runs/38620982627).
Both integration jobs passed. The tested source head was
[`c731faa`](https://github.com/roshan-amble/ssrf-lab/commit/c731faa0545b714f7862c58bf9376b2fd3638b91).
GitHub checked out the PR merge commit `2ea26b17981ae2788ae62bd01deef39e0ea7142e`,
which is recorded in each environment file. This snapshot is historical evidence,
not a result for later source changes.

Both Node **22.23.3** and **24.21.0** produced the same verdict totals:

| Client and tested configuration | Blocked | Prevented | Reached | N/A | Internal hits |
| --- | ---: | ---: | ---: | ---: | ---: |
| guarded-fetch 0.1.5, guarded fetch plus bounded body reader | 16 | 0 | 0 | 1 | 0 |
| n8n backend-network 1.17.3, request API, protection on | 12 | 0 | 0 | 1 | 0 |
| n8n backend-network 1.17.3, fetch API, protection on | 10 | 2 | 0 | 1 | 0 |

The two `PREVENTED` results are the credential-bearing direct URL and redirect.
No named n8n policy refusal was observed for those failures. The injected DNS
rebinding case is `N/A` in all three adapters. These results do not establish
full n8n workflow coverage, TLS coverage, or the absence of other SSRF flaws.
See [the integration scope](../../INTEGRATIONS.md).

All three protected clients received the successful entry control. Actual entry
hits were recorded for every applicable redirect and body probe. The negative
controls recorded **8** internal hits for native fetch, **10** for n8n's request
API with protection off, and **8** for its fetch API with protection off, on each
Node version. Both direct and redirected internal requests succeeded in every
negative control.

## Raw files

| Runtime | guarded-fetch | n8n | Network | Environment |
| --- | --- | --- | --- | --- |
| Node 22 | [JSON](node22/vercel.json) | [JSON](node22/n8n.json) | [Interfaces](node22/network.json), [routes](node22/routes.json) | [Environment](node22/environment.txt) |
| Node 24 | [JSON](node24/vercel.json) | [JSON](node24/n8n.json) | [Interfaces](node24/network.json), [routes](node24/routes.json) | [Environment](node24/environment.txt) |

Each directory also retains the installed versions, original n8n audit JSON,
and exact-fixture audit-gate output. The eight pre-existing dependency findings
are reviewed research exceptions, not new findings from these probes.

The downloaded archives were verified against GitHub's artifact digests before
extracting these files:

| Runtime | Artifact ID | ZIP SHA-256 |
| --- | --- | --- |
| Node 22 | 11922486931 | `fb724af9059296614b4447df0ad2e1ae7307ead99662fa3cecf3d57b8c823ce5` |
| Node 24 | 11921133158 | `c0b30242355699e4d692b7e4dff5e4b45868def5754ba34caf173f01578fd7c7` |

The lockfile digests inside both JSON reports match the committed lockfiles.
The checked-in files remain available after the workflow artifacts expire.
