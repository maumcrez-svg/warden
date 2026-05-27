// Shared lockfile parse types. Each per-ecosystem parser returns an
// array of LockfileEntry records — the minimal shape scanSupplyChain
// consumes. ADR 0016 §1 (coverage) + §3 (direct-vs-transitive).

export type LockfilePosition = 'direct' | 'transitive';

export type LockfileEcosystem = 'npm' | 'PyPI' | 'crates.io';

export type LockfileEntry = {
  readonly ecosystem: LockfileEcosystem;
  readonly name: string;
  readonly version: string;
  readonly position: LockfilePosition;
};

export type LockfileParseResult =
  | { readonly kind: 'ok'; readonly entries: ReadonlyArray<LockfileEntry> }
  | { readonly kind: 'error'; readonly message: string };
