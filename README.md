# ssrf-lab

A local attack range and a conformance checker for SSRF defenses in HTTP clients.

![ci](https://github.com/roshan-amble/ssrf-lab/actions/workflows/ci.yml/badge.svg)

Most SSRF material shows 1 payload against 1 endpoint. Production is harder in a
different way: a fetcher has several controls, and a log cannot tell you whether
a request was **refused by a control** or simply **failed on its own**. Those
look identical until the day the network changes and the attack lands.

`ssrf-lab` starts a small hostile range on loopback, drives any HTTP client
through 10 attacks, and reports which ones a control actually stopped.

```bash
npm run scan -- scan --client all
```

## What it is

```
        your client under test
                 │
                 ▼
   ┌──────────────────────────┐        ┌───────────────────────────┐
   │  PUBLIC range            │  302   │  INTERNAL service         │
   │  (stands for the         │ ─────▶ │  answers a canary string  │
   │   internet; the client   │        │  counts every hit         │
   │   is allowed to fetch it)│        │  nothing may reach it     │
   │                          │        └───────────────────────────┘
   │  redirects: loopback,    │
   │  decimal-IP, metadata,   │        ┌───────────────────────────┐
   │  private, credentials,   │ ─────▶ │  169.254.169.254          │
   │  endless loop            │        │  198.51.100.1             │
   │  payloads: gzip bomb,    │        │  (never answer)           │
   │  endless body, 1 B/s     │        └───────────────────────────┘
   └──────────────────────────┘
```

Two servers, not one, because a single origin cannot tell a control from an
accident: the client is **allowed** to fetch the public range, so anything that
arrives at the internal service arrived by attack.

## Quick start

```bash
git clone https://github.com/roshan-amble/ssrf-lab
cd ssrf-lab
npm install
npm run scan -- scan --client all
```

## Measured output

This is a real run, not an illustration. CI re-runs it on every push.

```
[+] BLOCKED    the client refused, and named the control that refused
[=] PREVENTED  the attack never arrived, but the client named no control
[!] REACHED    the client arrived, or never stopped reading
[~] LUCKY      nothing refused it; something else failed first
[-] N/A        the client has no hook this probe can use

node-fetch (global, defaults)
-----------------------------
  [!] REACHED    Redirect into loopback                        status 200, 31 bytes
  [!] REACHED    Redirect into loopback, written as a decimal  status 200, 31 bytes
  [=] PREVENTED  Redirect that carries credentials             cross origin not allowed for request mode "cors"
  [~] LUCKY      Redirect into cloud metadata                  no policy; the request failed
  [~] LUCKY      Redirect into a private range                 no policy; the request failed
  [+] BLOCKED    Endless redirect chain                        the client's own limit: redirect count exceeded
  [!] REACHED    Decompression bomb                            status 200, 67108864 bytes
  [!] REACHED    Body with no end and no length                status 200, 34942947 bytes; the harness had to stop the read
  [!] REACHED    One byte per second                           status 200, 3 bytes; the harness had to stop the read
  [-] N/A        DNS rebinding (simulated)                     the client exposes no hook on the address it connects to

  1 blocked · 1 prevented · 5 reached · 2 lucky · 1 not applicable

check-then-connect (naive guard)
--------------------------------
  [+] BLOCKED    Redirect into loopback                        forbidden-address: 127.0.0.1 (loopback)
  [+] BLOCKED    Redirect into loopback, written as a decimal  forbidden-address: 127.0.0.1 (loopback)
  [+] BLOCKED    Redirect that carries credentials             forbidden-address: 127.0.0.1 (loopback)
  [+] BLOCKED    Redirect into cloud metadata                  forbidden-address: 169.254.169.254 (link-local)
  [+] BLOCKED    Redirect into a private range                 forbidden-address: 198.51.100.1 (private)
  [+] BLOCKED    Endless redirect chain                        too-many-redirects: more than 3 hops
  [+] BLOCKED    Decompression bomb                            body-too-large: stopped after 1064960 bytes, cap is 1048576
  [+] BLOCKED    Body with no end and no length                body-too-large: stopped after 1048914 bytes, cap is 1048576
  [+] BLOCKED    One byte per second                           deadline: 4000 ms elapsed
  [!] REACHED    DNS rebinding (simulated)                     status 200, 31 bytes

  9 blocked · 0 prevented · 1 reached · 0 lucky · 0 not applicable

guarded client (this repo)
--------------------------
  [+] BLOCKED    Redirect into loopback                        forbidden-address: 127.0.0.1 is loopback
  [+] BLOCKED    Redirect into loopback, written as a decimal  forbidden-address: 127.0.0.1 is loopback
  [+] BLOCKED    Redirect that carries credentials             forbidden-address: 127.0.0.1 is loopback
  [+] BLOCKED    Redirect into cloud metadata                  forbidden-address: 169.254.169.254 is link-local
  [+] BLOCKED    Redirect into a private range                 forbidden-address: 198.51.100.1 is private
  [+] BLOCKED    Endless redirect chain                        too-many-redirects: more than 3 hops
  [+] BLOCKED    Decompression bomb                            body-too-large: stopped after 1064960 bytes, cap is 1048576
  [+] BLOCKED    Body with no end and no length                body-too-large: stopped after 1048914 bytes, cap is 1048576
  [+] BLOCKED    One byte per second                           deadline: 4000 ms elapsed
  [+] BLOCKED    DNS rebinding (simulated)                     deadline: 3000 ms elapsed

  10 blocked · 0 prevented · 0 reached · 0 lucky · 0 not applicable
```

## The verdicts, and why there are 5

| Verdict | Meaning |
| --- | --- |
| `BLOCKED` | The client refused, and named the control. This is the only verdict you can rely on. |
| `PREVENTED` | The attack never arrived, but no control was named. Measured with the internal service's hit counter, not guessed from an error. |
| `REACHED` | The client arrived at the internal service, or it never stopped reading. |
| `LUCKY` | Nothing refused it. The request failed for a reason outside the client. The same attack on a live network can land. |
| `N/A` | The client has no hook the probe needs, which is itself a finding. |

`LUCKY` is the reason this tool exists. In the run above, built-in `fetch` looks
safe against the cloud-metadata redirect. It is not: no control refused it, and
the address simply does not answer on a laptop. On an EC2 instance it answers.

## The probes

| Probe | The attack | The control it tests |
| --- | --- | --- |
| Redirect into loopback | `302` to the internal service | Judge every hop, not only the first URL |
| Redirect into loopback, as a decimal | `302` to `http://2130706433:PORT/` | Classify the parsed host, never the raw string |
| Redirect that carries credentials | `302` to `http://user:pass@127.0.0.1/` | Refuse the address, and never echo the credentials |
| Redirect into cloud metadata | `302` to `169.254.169.254` | Refuse link-local addresses |
| Redirect into a private range | `302` to `198.51.100.1` | Refuse private and reserved ranges |
| Endless redirect chain | `302` to itself | Cap the number of hops |
| Decompression bomb | 64 KiB on the wire, 64 MiB expanded | Count bytes after decompression, while reading |
| Body with no end and no length | chunked, never finishes | Cap received bytes with a running total |
| One byte per second | a response that stays open for hours | One deadline over the whole request |
| DNS rebinding (simulated) | first answer public, every later answer loopback | Judge the address the socket uses |

## The 4 controls in the guarded client

```ts
// 1. every hop is judged, not only the entry URL
for (const hop of redirects) refuseForbiddenLiteral(hop)

// 2. the address is judged where the socket connects, and pinned
const lookup = guardedLookup(base)   // a mixed answer is refused whole

// 3. the cap runs WHILE reading, and counts decompressed bytes
if ((bytes += chunk.length) > maxBytes) throw new PolicyRefusal('body-too-large', …)

// 4. one deadline covers the request AND the body read
const deadline = AbortSignal.timeout(timeoutMs)
```

Control 4 is the one that is usually wrong. A socket timeout is not a deadline:
the 1-byte-per-second target keeps the socket busy for ever and never trips it.

## Use it on your own client

```ts
import { startAttackRange, runScan, renderTable } from 'ssrf-lab'

const range = await startAttackRange()

const myClient = {
  name: 'my-fetcher',
  supportsConnectHook: false,
  async fetch(url, options) {
    /* call your fetcher, return { status, bytesRead, bodySample, hops, stoppedByHarness } */
  },
}

console.log(renderTable(await runScan(myClient, range)))
await range.close()
```

Throw `PolicyRefusal(reason, detail)` from your adapter when your client refuses
on purpose. That is how the checker tells a control from a failure.

## What this does NOT prove

- **The rebinding probe is simulated.** It swaps answers inside the process with
  an injected resolver. It proves whether a client judges the address it
  connects to. It proves nothing about a real recursive resolver or TTL 0.
- **Everything is loopback and plain HTTP.** There is no TLS in the range, so
  scheme-downgrade behaviour on a `https` → `http` redirect is untested.
- **`trustedOrigin` is a lab affordance.** The range lives on loopback, so the
  entry origin is exempt from the address rules. Without it a guard refuses the
  range itself and every probe passes while testing nothing. No production
  fetcher should have such an option.
- **A green scan is not a safe client.** These are 10 attacks, not the class.

## Design notes

- **Two servers.** The public range stands for the internet and may be fetched.
  The internal service may not. A hit on the internal service is therefore
  always an attack that landed.
- **A canary and a counter.** The body carries a canary so a hit is provable,
  and the internal service counts requests so a MISS is provable too. Watching
  only for errors cannot distinguish a control from an accident.
- **`198.51.100.1`, not `10.0.0.1`.** An early version used `10.0.0.1` and a
  probe reached a real device on the author's own network. The range now points
  at TEST-NET-2, which is reserved for documentation.

## Roadmap

- A real DNS server in the range, so rebinding is measured rather than simulated
- TLS on the range, for scheme-downgrade probes
- Adapters for `axios`, `got` and `undici` with explicit agents
- IPv6 targets, including `::ffff:127.0.0.1`

## License

MIT
