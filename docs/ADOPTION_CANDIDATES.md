# Candidate project inspection, 2026-10-19

This records source inspection and locally prepared trials. It does not count
as external adoption, maintainer acceptance, or independent user testing.

| Project and inspected revision | Existing coverage / setup | Decision |
| --- | --- | --- |
| [thegruber/linkpeek, 4ce9a53](https://github.com/thegruber/linkpeek/tree/4ce9a53f45baf99f3a0bd00a26f82b47c7eea031) | Typed private-network refusals, validated redirects, deterministic fixture/mock tests; optional live tests. Public API returns parsed metadata. | Prepare a real-request public `preview()` trial with entry/internal counters, successful HTML previews, an allowed redirect and a late-error control. |
| [OP-Engineering/link-preview-js, ab4a5af](https://github.com/OP-Engineering/link-preview-js/tree/ab4a5af1e5e1aaa3af3f2426dbcd6d8e9e0eadbb) | Redirect/address tests plus a separate real Node HTTPS connection-pinning fixture. Security configuration includes the caller's `resolveDNSHost` callback; default redirects are refused. | Defer a generic nine-case pitch. An additional contribution needs a specific gap beyond the existing pinning and redirect coverage. |
| [Dhaiwat10/rlp-proxy, 5c18415](https://github.com/Dhaiwat10/rlp-proxy/tree/5c18415247ea35aeccf07d1cffea87a85fb0760a) | Express app, Redis/Supabase setup, metadata-parser wrapper, no test script. The inspected source commit is from January 2022. | Deprioritize: substantial setup and an old source baseline make a quick maintainer adoption trial less practical. |

The [linkpeek trial](../integrations/linkpeek/README.md) exercises its unmodified
built public API. In the local direct-only smoke run, six address cases and
the separate credential policy were explicitly blocked with no internal hits;
an unsafe control reached the internal service, and the late-error control
remained `REACHED`. The subsequent full isolated trial passed on Node 22 and 24:
eight address/redirect refusals plus the separate credential refusal, zero
internal hits, successful previews and redirects, and working unsafe and
late-error controls. [Raw evidence and the separate upstream audit limitation](evidence/2026-10-19-linkpeek/README.md)
are retained in this repository.

No new vulnerability is claimed by these inspections. Contribution rules and
scope need to be rechecked before an upstream submission; an existing linkpeek
discussion already exists, so another generic introduction would be duplicate
outreach. A concrete tested artifact would provide new information instead.
