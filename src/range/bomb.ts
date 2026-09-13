import { gzipSync } from 'node:zlib'
import { CANARY_BOMB_TAIL } from './canaries.js'

/** Expanded size of the decompression bomb: 64 MiB. */
export const BOMB_EXPANDED_BYTES = 64 * 1024 * 1024

let cached: Buffer | null = null

/**
 * Build a gzip body that is small on the wire and large in memory.
 *
 * 64 MiB of zeros compresses to about 64 KiB, a ratio of about 1000:1. A
 * client that decompresses before it counts bytes allocates the whole 64 MiB,
 * and a real attacker picks a much larger number.
 *
 * The tail carries a canary, so a client that streamed the WHOLE body can be
 * told apart from one that stopped at a cap.
 */
export function decompressionBomb(): Buffer {
  if (cached !== null) return cached

  const zeros = Buffer.alloc(BOMB_EXPANDED_BYTES - CANARY_BOMB_TAIL.length, 0x30)
  const payload = Buffer.concat([zeros, Buffer.from(CANARY_BOMB_TAIL, 'utf8')])
  cached = gzipSync(payload, { level: 9 })
  return cached
}
