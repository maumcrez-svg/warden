import type { UnicodeSeverity } from '@warden-sh/rules';

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
