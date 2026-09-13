/**
 * Type shims for the SSRF-protection packages under test.
 *
 * They ship JavaScript without declarations, and the scan only needs the 1
 * function each README documents.
 */

declare module 'ssrf-req-filter' {
  import type { Agent } from 'node:http'
  const ssrfFilter: (url: string) => Agent
  export default ssrfFilter
}

declare module 'ssrf-agent' {
  import type { Agent } from 'node:http'
  const ssrfAgent: (url: string) => Agent
  export default ssrfAgent
}
