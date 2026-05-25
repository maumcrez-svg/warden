// Hash function for the manifest's `hash = "blake3:<hex>"` field.
// ADR 0012 §2 picks blake3 for speed + prefix-namespaced for future
// algorithm agility. Bun's built-in CryptoHasher does not support
// blake3 as of 1.3.x, so we depend on @noble/hashes (pure JS, zero
// transitive deps, paulmillr-audited).

import { blake3 } from '@noble/hashes/blake3.js';

export const HASH_PREFIX = 'blake3:';

export function hashFileContent(content: Uint8Array): string {
  const digest = blake3(content);
  let hex = '';
  for (let i = 0; i < digest.length; i++) {
    const byte = digest[i] as number;
    hex += byte.toString(16).padStart(2, '0');
  }
  return `${HASH_PREFIX}${hex}`;
}

export function parseHash(field: string): { algo: string; hex: string } | null {
  const idx = field.indexOf(':');
  if (idx <= 0) return null;
  const algo = field.slice(0, idx);
  const hex = field.slice(idx + 1);
  if (!/^[0-9a-f]+$/i.test(hex)) return null;
  return { algo, hex };
}
