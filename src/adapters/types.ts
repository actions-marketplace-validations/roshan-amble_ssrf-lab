import type { LookupFunction } from 'node:net'

/** Why a client refused a request. Each reason names the control that fired. */
export type RefusalReason =
  | 'forbidden-address'
  | 'too-many-redirects'
  | 'body-too-large'
  | 'deadline'
  | 'scheme-not-allowed'

/**
 * A refusal the CLIENT decided on.
 *
 * This is the type that separates a control from luck. A connection error is
 * not one of these, however convenient its timing.
 */
export class PolicyRefusal extends Error {
  constructor(
    readonly reason: RefusalReason,
    readonly detail: string,
  ) {
    super(`${reason}: ${detail}`)
    this.name = 'PolicyRefusal'
  }
}

export interface FetchOutcome {
  status: number
  /** Bytes of body the client accepted, after any decompression. */
  bytesRead: number
  /** First bytes of the body, kept so the checker can look for a canary. */
  bodySample: string
  /** Observed URLs in order. Opaque clients may expose only entry and final URLs. */
  hops: string[]
  /** True when the harness stopped the read because the client would not. */
  stoppedByHarness: boolean
}

export interface ClientOptions {
  /**
   * Replaces name resolution for this request.
   *
   * A probe uses this to answer a public address to the check and a loopback
   * address to the socket, which is DNS rebinding in one process.
   */
  lookup?: LookupFunction
  timeoutMs?: number
  maxBytes?: number
  /**
   * One origin that is treated as the public internet for the FIRST hop only.
   *
   * The range lives on loopback, so without this a guard refuses the range
   * itself and every probe passes while testing nothing. Redirect targets are
   * never covered by it. A production fetcher has no such option.
   */
  trustedOrigin?: string
}

export interface HttpClient {
  readonly name: string
  /**
   * Whether the adapter can exercise this lab's injected-resolver probe.
   * False does not mean the underlying client lacks its own DNS protection.
   */
  readonly supportsConnectHook: boolean
  /** False when the adapter cannot exempt the lab's loopback entry origin. */
  readonly supportsLoopbackOrigin?: boolean
  fetch(url: string, options?: ClientOptions): Promise<FetchOutcome>
}
