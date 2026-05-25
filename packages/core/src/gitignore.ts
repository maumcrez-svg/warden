// Minimal .gitignore -> glob-pattern converter for the M2 walker.
//
// Handles the common cases used by the warden repo's own .gitignore and
// typical AI-context-bearing projects:
//   - Comment lines (#...) and blank lines: skipped.
//   - Trailing `/` indicates directory only: yields `<p>/**`.
//   - Leading `/` anchors to the gitignore's directory: not prefixed `**/`.
//   - Unanchored patterns match anywhere in the tree: prefixed `**/`.
//   - File-name patterns yield both `<p>` and `<p>/**` (a file or its subtree).
//
// Negation patterns (`!...`) are recorded under `unsupported` so callers
// can warn. They are deliberately deferred — the warden repo does not use
// negation, and getting negation right means tracking pattern order. See
// docs/DECISIONS/0006-file-walker-and-format-detection.md §"Negation".

export type GitignoreParse = {
  readonly patterns: ReadonlyArray<string>;
  readonly unsupported: ReadonlyArray<string>;
};

export function parseGitignore(text: string): GitignoreParse {
  const patterns: string[] = [];
  const unsupported: string[] = [];

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    if (line.startsWith('!')) {
      unsupported.push(line);
      continue;
    }

    let p = line;
    const anchored = p.startsWith('/');
    if (anchored) p = p.slice(1);

    const isDirOnly = p.endsWith('/');
    if (isDirOnly) p = p.slice(0, -1);
    if (p === '') continue;

    const base = anchored ? p : `**/${p}`;
    if (isDirOnly) {
      patterns.push(`${base}/**`);
    } else {
      patterns.push(base);
      patterns.push(`${base}/**`);
    }
  }

  return { patterns, unsupported };
}
