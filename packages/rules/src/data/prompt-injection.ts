// warden: payload-fixture rules-data -- regex literals are attack strings by definition (ADR 0010)
//
// Prompt-injection rule pack. Each rule is a regex + tier + cited primary
// source. Threat ID T4 covers this family in docs/THREAT_MODEL.md
// (CVE-2025-53773; NVD entry verification is pending — citations here point
// at published academic work and the OWASP LLM Top 10 instead of the CVE
// payload itself).
//
// Tier model (see docs/DECISIONS/0008-prompt-injection-rule-pack.md):
//   - verbatim   : exact known-payload string or near-canonical phrasing;
//                  zero legitimate use in agent-context prose. high severity.
//   - suspicious : narrowly-scoped attack phrasing (persona-override style);
//                  legitimate prose can be written to avoid it. medium.
//   - stylistic  : pattern with attack-adjacent shape but plausible benign
//                  use; reported at low severity, advisory only.
//
// Pattern design rule: every pattern is scoped narrowly enough that the
// three M3 benign fixtures (academic-paper, fictional-dialogue,
// security-advisory) pass with zero findings. Broader detection — code-
// fence awareness, content-type gating — is sequenced post-MVP.
//
// IMPORTANT: when authoring rule citations or comments here, do NOT embed
// the verbatim attack strings the patterns are designed to catch (e.g. the
// canonical override-prior-context imperative, ChatML role markers). The
// scan-prompt-injection pipeline runs over this file via the dogfood test;
// self-triggering breaks the gate.

export type PromptInjectionTier = 'stylistic' | 'suspicious' | 'verbatim';
export type PromptInjectionSeverity = 'low' | 'medium' | 'high';

export type PromptInjectionRule = {
  readonly id: string;
  readonly threatIds: ReadonlyArray<'T4'>;
  readonly name: string;
  readonly tier: PromptInjectionTier;
  readonly severity: PromptInjectionSeverity;
  readonly pattern: RegExp;
  readonly citation: string;
  readonly verifiedDate: string;
};

export const PROMPT_INJECTION_RULES: ReadonlyArray<PromptInjectionRule> = [
  {
    id: 'prompt-injection.override-prior-instructions',
    threatIds: ['T4'],
    name: 'Override-prior-context directive',
    tier: 'verbatim',
    // Imperative form: "(verb) (qualifier?) (scope) (target)".
    //   verb     : ignore | disregard | forget | override
    //   qualifier: all | the | your
    //   scope    : previous | prior | preceding | above | earlier | initial | original | system
    //   target   : instructions | prompts | directives | messages | rules | context
    // Word boundaries on both ends prevent partial-word matches.
    pattern:
      /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|preceding|above|earlier|initial|original|system)\s+(?:instructions?|prompts?|directives?|messages?|rules?|context)\b/i,
    citation:
      'Perez & Ribeiro 2022, "Ignore Previous Prompt: Attack Techniques For Language Models" — arXiv:2211.09527',
    severity: 'high',
    verifiedDate: '2026-05-25',
  },
  {
    id: 'prompt-injection.role-override-persona',
    threatIds: ['T4'],
    name: 'Role-override persona shift',
    tier: 'suspicious',
    // "you are now X" where X is a known jailbreak persona or unrestricted-mode
    // keyword. Narrow alternation lets benign fictional dialogue
    // ("you are now beyond the borderlands") pass. DAN, developer mode,
    // jailbroken, unrestricted, uncensored are the recurring tokens in
    // public jailbreak prompt corpora.
    pattern:
      /\byou\s+are\s+now\s+(?:DAN\b|in\s+(?:developer|dev|admin|root|god|debug)\s+mode\b|jailbroken\b|unrestricted\b|uncensored\b|free\s+from\s+(?:all\s+)?(?:restrictions?|rules?|filters?|limitations?)\b|operating\s+without\s+(?:restrictions?|rules?|filters?|limitations?))/i,
    citation:
      'OWASP LLM Top 10 — LLM01:2025 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/',
    severity: 'medium',
    verifiedDate: '2026-05-25',
  },
  {
    id: 'prompt-injection.chatml-control-tokens',
    threatIds: ['T4'],
    name: 'ChatML control tokens',
    tier: 'verbatim',
    // ChatML role-delimiter tokens (start/end/sep). The literal sequence
    // appears in published OpenAI documentation for GPT-3.5-turbo prompt
    // construction; its appearance inside agent-context prose is the
    // boundary-confusion attack.
    pattern: /<\|im_(?:start|end|sep)\|>/,
    citation:
      'OpenAI ChatML role-token spec (openai-python repository, chatml.md, since removed); abused as inline role boundary injection per OWASP LLM01',
    severity: 'high',
    verifiedDate: '2026-05-25',
  },
  {
    id: 'prompt-injection.role-confusion-control-tokens',
    threatIds: ['T4'],
    name: 'Role-confusion control tokens',
    tier: 'verbatim',
    // Llama 2 instruction-format markers and ChatML named-role tokens.
    // Either family appearing inside untrusted prose is a boundary-
    // confusion injection: the model treats the embedded marker as a new
    // turn boundary.
    pattern: /<\|(?:system|user|assistant)\|>|\[\/?INST\]|<<\/?SYS>>/,
    citation:
      'Llama 2 [INST] instruction format (Meta, "Llama 2: Open Foundation and Fine-Tuned Chat Models" — arXiv:2307.09288) + ChatML role markers; OWASP LLM01',
    severity: 'high',
    verifiedDate: '2026-05-25',
  },
  {
    id: 'prompt-injection.system-role-prefix',
    threatIds: ['T4'],
    name: 'Leading system-role prefix',
    tier: 'stylistic',
    // Line-anchored "system:" prefix immediately followed by an imperative
    // or persona-setting verb. The benign uses of "system:" in normal
    // prose (e.g. a Slack message label) do not begin with these tokens.
    pattern:
      /^[ \t>*-]*system\s*:\s*(?:you\s+(?:are|will|must|may)|ignore|disregard|forget|override|the\s+(?:user|assistant|new))/im,
    citation:
      'Greshake et al. 2023, "Not what you\'ve signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" — arXiv:2302.12173',
    severity: 'low',
    verifiedDate: '2026-05-25',
  },
];
