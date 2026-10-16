# Action and recorded walkthrough evidence, 2026-10-16

Source: [`ac0d4906592a5c41c27785b7a4327d449bc10da9`](https://github.com/roshan-amble/ssrf-lab/commit/ac0d4906592a5c41c27785b7a4327d449bc10da9).

- [Action verification run](https://github.com/roshan-amble/ssrf-lab/actions/runs/38925644768): Node 22 and 24 both passed.
- [Full existing CI run](https://github.com/roshan-amble/ssrf-lab/actions/runs/38925644725): all four jobs passed.
- [Recording job](https://github.com/roshan-amble/ssrf-lab/actions/runs/38925644768/job/117056361377): Node 24.21.0, Linux 6.17.0-1022-azure.

The Action tests a consumer module under a directory containing spaces, and
checks that its outputs and JSON reports survive expected failures:

| Consumer | Result |
| --- | --- |
| Included guarded-fetch 0.1.5 example | 9 blocked, 0 internal hits, exit 0 |
| Native fetch | 8 reached, 8 internal hits, exit 1 |
| Always throws an unexplained error | Fails allowed-entry control, exit 2 |

The native-fetch credentials-in-URL case is `PREVENTED`, not `BLOCKED`: fetch
rejects the credential-bearing URL. The other eight requests reached the
fixture. That incidental failure does not turn the unsafe client into a pass.

## Recording provenance

The recording was captured by `scripts/record-demo.py --walkthrough` while
`scripts/walkthrough.mjs` executed the unsafe and protected checks inside a
loopback-only Linux network namespace. The public-looking entry address was
assigned to loopback, and the checker verified isolation before importing the
application module.

- [Timed terminal recording](walkthrough.cast)
- [Unedited terminal transcript](walkthrough.txt), including terminal clear codes
- [Unsafe command's raw JSON](walkthrough-unsafe.json)
- [Protected command's raw JSON](walkthrough-protected.json)
- [Rendered MP4](../../media/ssrf-lab-walkthrough.mp4)

The walkthrough prints a readable table derived from each command's captured
JSON. Row pacing and reading pauses are intentional parts of the recorded
program. The renderer adds a frame, a playback clock and a disclosure footer;
it does not fabricate commands, results, or a human typing session. The MP4
uses the original event timing at 12 fps, plus one second after process exit.

Re-render from the repository root with Python, Pillow, DejaVu fonts and ffmpeg:

```bash
python3 scripts/render-walkthrough.py \
  docs/evidence/2026-10-16-action/walkthrough.cast \
  docs/media/ssrf-lab-walkthrough.mp4
```

Scope is seven direct-address cases and two redirects. Both executions verify
a successful allowed-entry request and two native-fetch reach controls.
DNS rebinding, TLS, cross-origin credentials, arbitrary private-network
addresses and response-body limits are outside this starter check.
