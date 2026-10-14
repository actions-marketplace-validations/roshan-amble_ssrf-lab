# Additional target and patch verification

Selected, unedited artifact files from
[CI run 38650851198](https://github.com/roshan-amble/ssrf-lab/actions/runs/38650851198),
source head `619eaae84f63582441531694fe31d142f9c49fd3` and tested PR merge commit
`0dd366ebc28eba584d9ec5bbde06592c7f35636f`. Both integration jobs passed.

The same results were measured on Node 22.23.3 and 24.21.0:

| Unmodified package | Blocked | Prevented | Reached | N/A | Internal hits |
| --- | ---: | ---: | ---: | ---: | ---: |
| ssrf-safe-fetch 0.1.0 | 12 | 0 | 0 | 2 | 0 |
| ssrf-fetch 0.1.0 | 12 | 1 | 0 | 1 | 0 |
| @tak-ps/node-safeurl 1.8.0 | 13 | 0 | 0 | 1 | 0 |

All entry controls succeeded. Native-fetch negative controls reached the
internal service through direct and redirected URLs. Unsupported simulated DNS
checks are N/A; ssrf-safe-fetch also excludes TEST-NET space by documented
policy. ssrf-fetch's IPv4-mapped IPv6 case failed DNS lookup, so it is PREVENTED.
These are bounded observations, not comprehensive security assessments.

| Runtime | Raw comparison | Network | Audit |
| --- | --- | --- | --- |
| Node 22 | [JSON](node22/community.json) | [Interfaces](node22/network.json), [routes](node22/routes.json) | [Zero findings](node22/community-audit.json) |
| Node 24 | [JSON](node24/community.json) | [Interfaces](node24/network.json), [routes](node24/routes.json) | [Zero findings](node24/community-audit.json) |

## Verified functional fix

The [node-safeurl patch](../../../patches/node-safeurl/README.md) removes body
headers when a redirect rewrites the method to GET. Its three rewrite cases
fail on original upstream commit `274efcee2c288e313335ef4043236d490724a4d9` and
pass after the patch. Four method-preserving controls pass before and after.
The test runner also counts their parent, yielding 4 pass / 4 fail before and
8 pass / 0 fail after. The full patched upstream suite passes 198 tests on
each runtime. Lint and build also pass.

| Runtime | Before patch | After patch | Full patched suite |
| --- | --- | --- | --- |
| Node 22 | [TAP](node22/node-safeurl-regression-before.tap) | [TAP](node22/node-safeurl-regression-after.tap) | [198 passing](node22/node-safeurl-tests-after.tap) |
| Node 24 | [TAP](node24/node-safeurl-regression-before.tap) | [TAP](node24/node-safeurl-regression-after.tap) | [198 passing](node24/node-safeurl-tests-after.tap) |

Each directory also includes the original published-package/native-fetch
comparison, installed versions, environment, and build/lint logs. The functional
test uses an explicitly allowed local origin. It is not a demonstrated SSRF
bypass. The comparison continues using the original package; only the separate
upstream checkout receives the patch.

Archive digests were checked before extracting the files:

| Runtime | Artifact ID | ZIP SHA-256 |
| --- | --- | --- |
| Node 22 | 11934875782 | `47cd9555981a6978be7336459946f938f81e05753f3c32b855554751d3963407` |
| Node 24 | 11934920488 | `cdba9b64451dc17b12a67c58af47bbefc13b43097a2a3ae25e9fe57d7370b002` |

Both report lockfile digests match the committed community lockfile. Patch
SHA-256: `8fce8836eeafb3874bd75d3d3ec049f13ac3391dd75988782aa8ef4ad3c6784a`.
