# linkpeek public preview API trial

This trial calls the unmodified public `preview()` function from
[`linkpeek@2.1.5`, source 4ce9a53](https://github.com/thegruber/linkpeek/tree/4ce9a53f45baf99f3a0bd00a26f82b47c7eea031).
It complements that revision's fixture/mock security tests with real requests
to counted local fixtures. It is a compatibility demonstration prepared in
ssrf-lab, not a maintainer-run trial or evidence of adoption.

The normal calls keep the default private-address policy, redirect behavior,
and fetch implementation. The configured five-second timeout limits test
duration and is not credited as a security refusal.

## Scope and controls

- Six non-credential direct address forms and two redirects must produce the
  typed `PRIVATE_NETWORK_BLOCKED` error with zero measured internal requests.
- A seventh direct case checks embedded credentials separately. Its specific
  `INVALID_URL` rejection is attributed to the credential policy, not to IP
  classification.
- A successful allowed-entry request proves that a refused initial origin
  cannot silently stand in for redirect coverage. Every attack redirect must
  make one entry-server request.
- Separate local HTML fixtures must produce the expected preview title, both
  directly and through an allowed same-origin redirect. A client that refuses
  all requests or all redirects does not satisfy these controls.
- Native fetch must reach through one direct URL and one redirect.
- A deliberate control calls `preview()` with its documented private-IP
  opt-out, then throws after receiving the response. The checker must still
  report `REACHED` using the internal counter. The opt-out is confined to this
  unsafe control and only runs against the isolated local fixture.

Because `preview()` returns parsed metadata, the adapter cannot inspect raw
HTTP body bytes or response canaries. The adapter's `bytesRead: 0` and empty
`bodySample` are placeholders, not measurements. Only internal-target probes
are selected, and the independent request counter is the reach evidence.

DNS rebinding, arbitrary private destinations, TLS, response-resource limits,
and the metadata parser's broader correctness are outside this trial. The
upstream security policy already documents DNS/connect limitations; this trial
does not present them as a new finding.

## Reproduce

Use a disposable Linux environment with Node 22.21+ or 24. Install and build
before entering the network namespace:

```bash
npm ci --ignore-scripts
npm run build
git clone https://github.com/thegruber/linkpeek.git consumer
git -C consumer checkout --detach 4ce9a53f45baf99f3a0bd00a26f82b47c7eea031
(cd consumer && npm ci --ignore-scripts && npm run quality)
sudo env "PATH=$PATH" unshare --net -- bash -euo pipefail -c '
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  node integrations/linkpeek/verify.mjs --module consumer/dist/index.js
'
```

The runner checks the package version and source commit, and verifies network
isolation before importing the consumer. The
[Node 22/24 workflow](../../.github/workflows/linkpeek-source.yml) runs the
upstream quality gate first and retains the JSON report even on a failed check.

For a limited local smoke check without namespace support:

```bash
node integrations/linkpeek/verify.mjs --direct-only --module consumer/dist/index.js
```

That smoke check covers only the seven direct cases and the direct unsafe and
late-error controls. It omits successful public-entry, HTML, safe-redirect, and
attack-redirect coverage. Exit codes: 0 means all selected refusals were
explicit; 1 means measured internal reach; 2 means an inconclusive selected case.

Codex assisted with implementation, testing and documentation.
