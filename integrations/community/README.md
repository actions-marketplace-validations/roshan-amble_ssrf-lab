# Additional published-package comparisons

[Recorded Node 22 and 24 results, including the before/after patch proof](../../docs/evidence/2026-10-14-619eaae/README.md).

| Target | Pinned version | Upstream |
| --- | --- | --- |
| ssrf-safe-fetch | 0.1.0 | [Chinozilla/ssrf-safe-fetch](https://github.com/Chinozilla/ssrf-safe-fetch) |
| ssrf-fetch | 0.1.0 | [iansduncan-oss/ssrf-fetch](https://github.com/iansduncan-oss/ssrf-fetch) |
| @tak-ps/node-safeurl | 1.8.0 | [dfpc-coe/node-safeurl](https://github.com/dfpc-coe/node-safeurl) |

Each adapter calls the unmodified published fetch function with upstream default
policy and no allowlist. Package versions are checked against the installation;
the separate lockfile pins transitive dependencies. These dependencies are not
added to the default CLI installation. Use Node 22.19.0 or newer for this optional
group, matching node-safeurl's engine requirement.

```bash
npm ci --ignore-scripts
npm run build
npm ci --ignore-scripts --prefix integrations/community
node integrations/community/verify.mjs --direct-only
```

The full comparison requires the [isolated entry fixture](../../docs/INTEGRATIONS.md):

```bash
sudo env "PATH=$PATH" unshare --net -- bash -euo pipefail -c '
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  node integrations/community/verify.mjs
'
```

The group tests seven direct forms, five address redirects, a redirect loop,
and the applicability of the existing simulated rebinding probe. Each client
must first complete a successful entry request. Per-probe entry/internal hit
counts and native-fetch negative controls are saved in the JSON.

Scope and classification:

- ssrf-fetch intentionally rejects every redirect. Its exact `unexpected
  redirect` error is recorded as `redirect-not-allowed`, not a destination-specific
  IP classification. Its IPv4-mapped IPv6 direct URL currently fails DNS lookup
  with `ENOTFOUND`; the adapter records that as `PREVENTED`, not `BLOCKED`.
- ssrf-safe-fetch explicitly excludes TEST-NET addresses in its README. That
  case is `N/A`. The README also documents its DNS check/connect limitation;
  this comparison does not present that limitation as a new discovery.
- DNS rebinding is `N/A` because these adapters do not exercise an injected
  resolver across both validation and connection. TLS and response-resource
  limits are not covered. The 5-second deadline and 1 MiB read bound belong
  to the harness and are never credited as target policy controls.
- DNS errors are not treated as policy refusals, including when a target
  reports them through the same error class as an address refusal.
- The separate dependency audit has no exceptions. CI fails on any advisory
  reported by `npm audit` for this group.

`check-redirects.mjs` is an additional functional comparison for node-safeurl's
method rewrites. It uses one explicitly allowed loopback origin and compares
the original package against native fetch. The
[prepared fix and regression tests](../../patches/node-safeurl/README.md) address
stale body headers after redirects. The patch is tested against upstream source
in a separate checkout, leaving this package comparison unmodified.
