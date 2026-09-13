import type { Agent } from 'node:http'
import { useAgent } from 'request-filtering-agent'
import ssrfAgent from 'ssrf-agent'
import ssrfFilter from 'ssrf-req-filter'
import { agentClient } from './agentClient.js'
import type { HttpClient } from './types.js'

/**
 * Third-party npm packages whose stated purpose is to stop SSRF.
 *
 * A library that never claimed to block anything is not interesting here.
 * These 3 do claim it, so a probe that reaches the internal service through
 * one of them is a finding, not a configuration mistake.
 */

export const requestFilteringAgent: HttpClient = agentClient({
  name: 'request-filtering-agent (npm)',
  makeAgent: (url) => useAgent(url) as Agent,
  refusalPattern: /not allowed|private|reserved|blocked/i,
})

export const ssrfReqFilter: HttpClient = agentClient({
  name: 'ssrf-req-filter (npm)',
  makeAgent: (url) => ssrfFilter(url) as Agent,
  refusalPattern: /not allowed|private|reserved|blocked|call.*blocked/i,
})

export const ssrfAgentClient: HttpClient = agentClient({
  name: 'ssrf-agent (npm)',
  makeAgent: (url) => ssrfAgent(url) as Agent,
  refusalPattern: /not allowed|private|reserved|blocked|forbidden/i,
})
