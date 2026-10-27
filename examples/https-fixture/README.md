# HTTPS fixture prototype

A small fixture for developing HTTPS regression tests before connecting an
application fetcher. It exercises ssrf-lab's existing reference guarded client
and deliberately unsafe controls. It does not test Vyana or any other application.

Two real HTTPS listeners use port 443: a public-looking address assigned only to
loopback in an isolated Linux network namespace, and a prohibited loopback
destination. A temporary CA signs a certificate for two synthetic `.test`
hostnames. An injected resolver supplies deterministic addresses to the clients;
no public DNS or pharmacy site is contacted.

The destination separately counts TCP connections, completed TLS handshakes and
HTTP requests. A measured internal request remains `REACHED` after a late policy
error. A connection that reaches the internal listener without an HTTP request is
reported as `CONTACTED`, not a successful block.

## Run

Use a disposable Linux environment with Node 22 or 24, OpenSSL, `ip` and permission
to create a network namespace. Install and build before entering isolation:

```bash
npm ci --ignore-scripts
npm run build
sudo env "PATH=$PATH" unshare --net -- bash -euo pipefail -c '
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  node examples/https-fixture/verify.mjs
'
```

The script fails before starting listeners if isolation cannot be verified.
There is no unrestricted fallback. It generates temporary keys, starts a child
Node process with `NODE_EXTRA_CA_CERTS` pointing to the test CA, and removes the
keys when that process finishes. No system trust store is changed. Node reads
[extra CAs at process launch](https://nodejs.org/api/cli.html#node_extra_ca_certsfile);
normal chain and hostname verification stay enabled.

The JSON report and exit status establish ten checks:

- An allowed HTTPS request succeeds with a valid chain and matching hostname.
- A private hostname, HTTPS redirect to it, and an allowed hostname with a
  private resolver answer are refused without an internal TCP connection.
- Unsafe direct, redirect and same-hostname controls reach the internal counter.
- A refusal thrown after a measured request cannot erase that request.
- An untrusted CA and a hostname mismatch are `TLS_FAILURE`, never `BLOCKED`.

Exit 0 means all prototype checks passed, 1 means an assertion failed, and 2
means setup or measurement could not establish coverage. The
[workflow](../../.github/workflows/https-fixture.yml) retains the exact revision,
network inventory and measured report for Node 22 and 24, without private keys.

## Connecting an application later

Use the application's actual fetch function and its existing resolver and CA
trust mechanisms. Preserve its production allowlist, scheme, port and redirect
policy. Confirm the interface with its maintainer before adding an adapter.
The prototype's synthetic hostnames are fixtures, not production allowlist entries.

This fixture does not establish real DNS-rebinding protection, IPv6 coverage,
mixed DNS answers, HTTPS downgrade policy, robots behavior, price parsing or
production safety. Its resolver is injected and its clients are reference
controls. The existing npm CLI, HTTP starter and reusable Action are unchanged;
their recorded scope still excludes TLS.
