# node-safeurl redirect body-header fix

Target: `@tak-ps/node-safeurl@1.8.0`, upstream source
[`274efcee2c288e313335ef4043236d490724a4d9`](https://github.com/dfpc-coe/node-safeurl/commit/274efcee2c288e313335ef4043236d490724a4d9).

The wrapper changes POST to GET after 301/302 and non-GET/HEAD methods to GET
after 303, but leaves the original body headers in place after discarding the
body. The receiving local server observes `Content-Type: text/plain` on the
empty GET, whereas native fetch removes it. The same issue affects the other
request-body headers. This is a functional redirect-conformance bug, not a
confirmed SSRF bypass.

The [Fetch redirect algorithm](https://fetch.spec.whatwg.org/#http-redirect-fetch)
requires removing request-body headers when rewriting the request to GET.
The [patch](redirect-body-headers.patch) copies the caller's headers into a
`Headers` instance, then removes Content-Encoding, Content-Language,
Content-Location, Content-Type, and stale Content-Length when the method changes.
Other headers are preserved. It supports object, tuple-array, and Headers inputs
without mutating the caller's object. It does not change the URL checks.

Seven network regression cases exercise three method rewrites and four
method-preserving redirects. The three rewrite cases fail on the original
source and pass with the patch; the four controls pass both before and after.
The full upstream suite passed locally with 198 tests, plus lint and build.
CI repeats the before/after regression and full patched suite on Node 22 and 24.

To reproduce the published-package comparison from the ssrf-lab root:

```bash
npm ci --ignore-scripts --prefix integrations/community
node integrations/community/check-redirects.mjs
```

To apply the patch in an upstream checkout:

```bash
git checkout 274efcee2c288e313335ef4043236d490724a4d9
npm ci --ignore-scripts
git apply /absolute/path/to/ssrf-lab/patches/node-safeurl/redirect-body-headers.patch
npm run lint
npm run build
node --import tsx --test test/*.ts
```

All added regression requests use one explicitly allowed loopback origin.
The patch is prepared for maintainer review; it has not been submitted or merged
upstream. The community comparison continues testing the unmodified published
package, so the fix cannot improve its recorded baseline results.
