# Prompt Injection: A Survey of Attack Vectors

## Abstract

We survey the literature on adversarial inputs to large language models
that re-task the model away from its operator-specified behavior. Direct
attacks supply a competing directive in the user message; indirect attacks
embed the same directive in a retrieved document, a tool output, or
metadata such as a pull-request description. Both families exploit the
same underlying primitive: the model has no reliable mechanism to
distinguish trusted from untrusted content within its prompt window.

## Background

Foundational work by Perez and Ribeiro [arXiv:2211.09527] catalogued the
direct case. Greshake and colleagues [arXiv:2302.12173] generalised it to
the indirect setting, where the attacker never holds a conversational
turn with the model at all.

## Method

We avoid reproducing verbatim payloads in this manuscript. Each attack is
described by its canonical shape — its grammatical structure, lexical
markers, and the resource it targets — and not by an exact string. This
follows the responsible-disclosure norm established by the cited works
and by the OWASP LLM Top 10 community.

## Findings

Three patterns recur across our corpus of public jailbreak prompts:

1. Imperative override directives addressed at the model's instruction
   register. These compose a verb of negation, an anchor referring to
   earlier content, and a noun naming the target.
2. Persona-shift prompts that recast the assistant as an alternative
   character with relaxed safety constraints.
3. Role-confusion control-token leakage, where chat-format delimiters
   appear inside the body of an attacker-controlled document.

## Limitations

This work does not measure attack success rates on contemporary frontier
models. Such measurements require access controls beyond our remit.

## References

- Perez and Ribeiro 2022, arXiv:2211.09527
- Greshake et al. 2023, arXiv:2302.12173
- OWASP LLM Top 10 — LLM01:2025
