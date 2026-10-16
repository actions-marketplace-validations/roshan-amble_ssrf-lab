# Test your Node.js fetcher for SSRF in GitHub Actions

A request throwing an error does not tell you whether it reached an internal
service first. If your link-preview service, URL importer or webhook sender
accepts a user-supplied destination, that difference matters.

I built [ssrf-lab](https://github.com/roshan-amble/ssrf-lab) to make that difference
observable. This walkthrough connects a Node.js fetch function to an isolated
fixture, proves that an unprotected client reaches it, and turns the result
into a pull-request check.

The starter covers **seven direct-address cases and two redirects**. It does
not test DNS rebinding or TLS, and a passing result is not a complete security
assessment.

## What the check measures

The fixture has an entry service and a separate internal service. The internal
service counts requests independently of the client. If it received a request,
a later exception cannot change that result into a successful block.

The CI check also requires two kinds of controls:

- The application's allowed request must return the real entry response. A
  fetcher that rejects everything cannot pass.
- Native fetch must reach the internal service directly and through a
  redirect. A fixture that nobody can reach cannot produce a false green.

Each attack case then needs an explicit address-policy refusal and zero
contradictory internal hits. DNS errors, connection failures and timeouts do
not establish that the address policy worked.

## 1. Run the working example

Use Node.js 22.19 or newer. From a disposable development environment:

```bash
git clone https://github.com/roshan-amble/ssrf-lab.git
cd ssrf-lab
git checkout ac0d4906592a5c41c27785b7a4327d449bc10da9
npm ci --ignore-scripts
npm run build
node examples/custom-fetcher/check.mjs
```

The included application module calls pinned `guarded-fetch@0.1.5`. This local
smoke test covers the seven direct-address cases. Expect explicit refusals,
zero internal hits from the tested client, and exit `0`. Local address behavior
can vary by operating system; the isolated CI run below is the reproducible
nine-case check.

Now deliberately remove the protection:

```bash
node examples/custom-fetcher/check.mjs --unsafe
```

This uses native fetch as a control. Expect internal reach and exit `1`. An
unsafe client is supposed to fail the gate.

[Watch the recorded isolated execution](https://github.com/roshan-amble/ssrf-lab/blob/main/docs/media/ssrf-lab-walkthrough.mp4).
The recording uses the nine-case CI fixture; it includes real command output
and intentional reading pauses. The raw JSON and timed terminal transcript
are linked from the [recording evidence](../evidence/2026-10-16-action/README.md).

## 2. Connect the fetcher your application actually uses

Create `test/ssrf-fetcher.mjs` in your application. The harness needs a module
that exports `fetchUrl(url, { signal, timeoutMs })` and returns a real
fetch-compatible `Response`.

For the working guarded-fetch example, the core looks like this:

```js
import {
  createGuardedDispatcher,
  guardedFetch,
  GuardedFetchError,
} from 'guarded-fetch'

const dispatcher = createGuardedDispatcher()

export function fetchUrl(url, { signal, timeoutMs }) {
  return guardedFetch(url, {
    signal, timeoutMs, dispatcher, opaqueErrors: true,
  })
}

export function classifyRefusal(error) {
  if (!(error instanceof GuardedFetchError)) return undefined
  if (['hostname_unsafe', 'host_not_allowed', 'redirect_to_unsafe_host']
    .includes(error.code)) {
    return 'forbidden-address'
  }
}

export async function close() {
  await dispatcher.destroy()
}
```

For your application, replace the implementation with an import of its
existing fetch function and configuration. Map only its genuine address-policy
error. Do not put a new blocker into the adapter just to make the test pass.
The goal is to test the code you ship.

If your public helper returns parsed data, use its lower-level HTTP function
that returns a `Response`. Preserve redirect handling and honor cancellation
or a finite timeout. See the [full module contract](../../examples/custom-fetcher/README.md).

## 3. Add the pull-request check

After committing that module, add this workflow to your application as
`.github/workflows/ssrf.yml`:

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
      - name: Check the application's fetcher
        id: ssrf
        uses: roshan-amble/ssrf-lab@ac0d4906592a5c41c27785b7a4327d449bc10da9
        with:
          fetcher-module: test/ssrf-fetcher.mjs
      - name: Save the report, including failed checks
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ssrf-report
          path: |
            ${{ steps.ssrf.outputs.report-path }}
            ${{ steps.ssrf.outputs.errors-path }}
          if-no-files-found: warn
```

Adjust the application install/build steps to match your project. For a
monorepo, set the Action's `working-directory` input to the application folder;
`fetcher-module` is resolved relative to that directory.

The Action installs its own pinned harness, creates a Linux network namespace
with only loopback enabled, and runs the check there. The fixture's entry
address, `93.184.216.34`, is assigned to loopback inside that namespace. It does
not send the test to an external service at that address.

The check verifies isolation before importing the application module. Use the
provided GitHub-hosted Ubuntu setup. Network isolation contains the traffic;
it is not a sandbox for untrusted application code.

## 4. Read failures correctly

| Exit code | Meaning | Next step |
| --- | --- | --- |
| `0` | Every selected attack case produced an explicit address refusal, with no internal reach. | Keep the regression check in CI. |
| `1` | At least one attack request reached the internal fixture. | Inspect the per-probe report and the application's policy. |
| `2` | Setup/control failure or inconclusive coverage. | Fix the setup or explain the result before claiming protection. |

The artifact contains per-probe verdicts, entry/internal request counts,
runtime information and controls. Report paths are produced even when the
check fails; dependency installation failures occur before a report exists.

If your application requires HTTPS, a specific hostname allowlist, or network
access during initialization, this fixture may fail its allowed-entry control.
Keep the production policy intact and adapt the fixture deliberately.

## What this establishes

This gives you a repeatable test for a defined set of address and redirect
cases. It does not cover DNS rebinding, TLS, cross-origin credentials,
arbitrary private-network addresses or response-body limits.

Try the [working example](https://github.com/roshan-amble/ssrf-lab/tree/main/examples/custom-fetcher)
and connect one real fetcher. If the fixture does not fit, an issue with your
fetcher type, expected policy and the failing case is useful feedback.

If the project is useful, a GitHub star helps you find it again and follow new
coverage: [roshan-amble/ssrf-lab](https://github.com/roshan-amble/ssrf-lab).

*Disclosure: Codex assisted with the implementation, test execution, recording
and writing. Results are linked to the captured CI output.*
