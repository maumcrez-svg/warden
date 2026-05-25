// Build the byte sequence that gets signed. ADR 0012 §2: signing is
// over `path || hash` so that swapping path or content produces a
// different signed message — signature reuse across paths or content
// swaps is structurally detectable, not just hash-detectable.
//
// Concretely: `<path>\n<hash>` (newline separator). The newline is
// the unambiguous delimiter; neither path nor hash contains a literal
// newline (paths are repo-relative forward-slash strings; hash is
// `blake3:<hex>`), so the message is uniquely parseable.

export const SSH_SIGN_NAMESPACE = 'warden';

export function buildSignMessage(path: string, hash: string): Uint8Array {
  return new TextEncoder().encode(`${path}\n${hash}`);
}
