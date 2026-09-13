/**
 * Canaries are the proof that a client REACHED something it should not have.
 *
 * A probe that only watches for an error cannot tell a control from bad luck:
 * a connection to a dead address fails on its own. A canary in the response
 * body is positive evidence that the request completed.
 */
export const CANARY_INTERNAL_SECRET = 'SSRF-LAB-CANARY-INTERNAL-SECRET'

/** Returned by the body that a size cap must never finish reading. */
export const CANARY_ENDLESS_CHUNK = 'SSRF-LAB-CANARY-ENDLESS'

/** Returned by the decompression bomb once it is fully expanded. */
export const CANARY_BOMB_TAIL = 'SSRF-LAB-CANARY-BOMB-TAIL'
