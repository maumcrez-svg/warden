import type {
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
