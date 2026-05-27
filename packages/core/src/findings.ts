import type {
  McpSeverity,
  PromptInjectionSeverity,
  PromptInjectionTier,
  UnicodeSeverity,
} from '@warden-sh/rules';

// `info` is the system-wide severity tier introduced by M9 / ADR 0016 §4.
// ADR 0011 §4 had deferred `info` "until a rule needs it"; the rule that
// needs it is `supply-chain.osv-known-vulnerability` for the transitive
// LOW position-of-dependency case. Other detectors continue to emit only
// high/medium/low (their existing severity unions are unchanged).
export type SupplyChainSeverity = 'high' | 'medium' | 'low' | 'info';

export type UnicodeFindingKind = 'always-suspicious' | 'density-violation';

export type UnicodeFinding = {
  readonly ruleId: string;
  readonly threatIds: ReadonlyArray<string>;
  readonly rangeName: string;
  readonly codepoint: number;
  readonly byteOffset: number;
  readonly severity: UnicodeSeverity;
  readonly kind: UnicodeFindingKind;
};

export type PromptInjectionFinding = {
  readonly ruleId: string;
  readonly threatIds: ReadonlyArray<string>;
  readonly ruleName: string;
  readonly tier: PromptInjectionTier;
  readonly severity: PromptInjectionSeverity;
  readonly byteOffset: number;
  readonly byteLength: number;
  readonly match: string;
};

export type McpFinding = {
  readonly ruleId: string;
  readonly threatIds: ReadonlyArray<string>;
  readonly ruleName: string;
  readonly severity: McpSeverity;
  readonly serverName: string | null;
  readonly evidence: string;
  // Byte offset is set to 0 for MCP findings: the parsed JSON structure
  // does not preserve source positions, and surfacing a precise byte
  // location would require a JSON tokenizer (out of scope for M4).
  // Reporters fall back to "evidence" text for human review.
  readonly byteOffset: 0;
};

// Lockfile-based supply-chain finding (ADR 0016 §5). Emitted by
// `scanSupplyChain` after a lockfile entry matches the loaded OSV index
// for its ecosystem.
export type SupplyChainFinding = {
  readonly ruleId: 'supply-chain.osv-known-vulnerability';
  readonly threatIds: ReadonlyArray<string>; // ['T6']
  readonly severity: SupplyChainSeverity;
  readonly ecosystem: 'npm' | 'PyPI' | 'crates.io';
  readonly packageName: string;
  readonly version: string;
  readonly position: 'direct' | 'transitive';
  readonly advisoryId: string;
  readonly advisoryUrl: string;
  readonly summary: string;
  readonly confidence: 'in-range' | 'version-unknown';
  // Byte offset of 0: surfacing the precise lockfile byte location of
  // the version string would require a per-format tokenizer (TOML byte
  // offsets, JSON byte offsets). Deferred — reporters fall back to
  // ecosystem + package + version for human review.
  readonly byteOffset: 0;
};
