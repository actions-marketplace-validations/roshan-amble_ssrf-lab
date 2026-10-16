# SSRF Lab GitHub Action

Run the application's actual Node.js fetcher against seven direct-address cases
and two redirects. Each run uses a fresh loopback-only Linux network namespace.
The internal service counts requests independently of the client's result.

Use a disposable GitHub-hosted Ubuntu runner and Node.js 22.19+ or 24. Install
and build your application first. The Action builds its own pinned harness,
creates the namespace, checks the allowed-entry and unsafe-fetch controls,
and fails for internal reach or inconclusive coverage.

The application's module must export `fetchUrl(url, { signal, timeoutMs })` and
return a real fetch-compatible Response. An optional `classifyRefusal(error)`
can return `forbidden-address` for a genuine address-policy error. See the
[complete module contract](../examples/custom-fetcher/README.md).

```yaml
name: SSRF regression check
on: [pull_request, push]
permissions:
  contents: read
jobs:
  ssrf:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: actions/setup-node@v5
        with:
          node-version: '24'
          cache: npm
      - run: npm ci
      - run: npm run build --if-present
      - name: Test the application fetcher
        id: ssrf
        uses: roshan-amble/ssrf-lab@ACTION_COMMIT
        with:
          fetcher-module: test/ssrf-fetcher.mjs
      - name: Preserve the result, including failed checks
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ssrf-report
          path: |
            ${{ steps.ssrf.outputs.report-path }}
            ${{ steps.ssrf.outputs.errors-path }}
          if-no-files-found: warn
```

Replace `ACTION_COMMIT` with the tested Action commit listed in the tutorial.
Use an immutable commit pin when adopting the Action.

| Input | Meaning |
| --- | --- |
| `fetcher-module` | Required module path relative to `working-directory`; absolute paths also work. |
| `working-directory` | Application directory relative to the checkout. Defaults to `.`. |

| Output | Meaning |
| --- | --- |
| `report-path` | Unique absolute JSON path in the runner's temporary directory. |
| `errors-path` | Unique absolute error log path in the same directory. |
| `exit-code` | `0`: all selected cases explicitly blocked; `1`: internal request observed; `2`: inconclusive or setup failure. |

Outputs are produced by the check step even when it fails. Dependency
installation/build failures occur before that step, and have no report.
The Action does not install or build the consumer application and does not
upload artifacts automatically. Use the final step above to retain reports.

A client that blocks the entry URL, requires HTTPS, or needs external network
access to initialize will fail the fixture's controls. Keep the production
policy intact; this fixture may not fit that application.

Coverage excludes DNS rebinding, TLS, cross-origin credentials, arbitrary
private-network destinations, and body/timeout policy. Network isolation
contains the test traffic; application code still runs on the CI host. This is
a bounded regression test, not a security certification.
