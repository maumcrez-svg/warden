import type {
  McpSeverity,
  PromptInjectionSeverity,
  PromptInjectionTier,
  UnicodeSeverity,
} from '@warden-sh/rules';

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
