import type { Agent } from 'node:http'
import { agentClient } from './agentClient.js'
import { loadOptional, type OptionalPackage } from './optional.js'
import type { ClientOptions, HttpClient } from './types.js'

/**
 * Third-party npm packages whose stated purpose is to stop SSRF.
 *
 * A library that never claimed to block anything is not interesting here.
 * These 3 do claim it, so a probe that reaches the internal service through
 * one of them is a finding, not a configuration mistake.
 *
 * Each package is loaded on the first request, not at import time, so that
 * ssrf-lab runs without them. See `optional.ts`.
 */

export const requestFilteringAgent: HttpClient = lazyAgentClient(
  'request-filtering-agent (npm)',
  /not allowed|private|reserved|blocked/i,
  'request-filtering-agent',
  async () => {
    const { useAgent } = await import('request-filtering-agent')
    return (url) => useAgent(url) as Agent
  },
)

export const ssrfReqFilter: HttpClient = lazyAgentClient(
  'ssrf-req-filter (npm)',
  /not allowed|private|reserved|blocked|call.*blocked/i,
  'ssrf-req-filter',
  async () => {
    const ssrfFilter = (await import('ssrf-req-filter')).default
    return (url) => ssrfFilter(url) as Agent
  },
)

export const ssrfAgentClient: HttpClient = lazyAgentClient(
  'ssrf-agent (npm)',
  /not allowed|private|reserved|blocked|forbidden/i,
  'ssrf-agent',
  async () => {
    const ssrfAgent = (await import('ssrf-agent')).default
    return (url) => ssrfAgent(url) as Agent
  },
)

type MakeAgent = (url: string) => Agent

function lazyAgentClient(
  name: string,
  refusalPattern: RegExp,
  packageName: OptionalPackage,
  load: () => Promise<MakeAgent>,
): HttpClient {
  let makeAgent: MakeAgent | undefined

  const client = agentClient({
    name,
    refusalPattern,
    makeAgent: (url) => {
      if (makeAgent === undefined) throw new Error(`${packageName} was not loaded before the request`)
      return makeAgent(url)
    },
  })

  return {
    name: client.name,
    supportsConnectHook: client.supportsConnectHook,
    async fetch(url: string, options?: ClientOptions) {
      // Load outside agentClient's error mapping: a missing package must not be
      // mistaken for the library's own refusal wording.
      makeAgent ??= await loadOptional(packageName, load)
      return client.fetch(url, options)
    },
  }
}
