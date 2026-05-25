#!/usr/bin/env bash
# pre-commit-secrets.sh
#
# Blocks Bash tool calls that would commit obvious secrets to git.
# Triggers on `git commit` / `git commit -a` / `git commit -m ...`.
# Greps the staged diff against a small allowlist of high-confidence
# credential patterns.
#
# Exit codes:
#   0 — pass (not a git commit, no staged diff, or no secrets found)
#   2 — block (secrets detected; Claude must abort)
#
# Patterns chosen for very low false-positive rate. Tune by adding new
# patterns to the PATTERNS array with citations in code comments.

set -euo pipefail

INPUT="$(cat)"

# Extract the command from the tool input. Use jq when present, fall back
# to a constrained sed expression that does not need jq.
if command -v jq >/dev/null 2>&1; then
  COMMAND="$(echo "$INPUT" | jq -r '.tool_input.command // empty')"
else
  COMMAND="$(echo "$INPUT" \
    | grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed -E 's/^"command"[[:space:]]*:[[:space:]]*"(.*)"$/\1/' \
    | head -n1)"
fi

# Only act on git commit invocations.
if ! echo "$COMMAND" | grep -qE '\bgit[[:space:]]+commit\b'; then
  exit 0
fi

# Skip silently if we are not inside a git repository.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  exit 0
fi

# High-confidence credential patterns. Each one is annotated with the
# upstream identifier convention so a reviewer can verify it.
PATTERNS=(
  'AKIA[0-9A-Z]{16}'                           # AWS access key — AWS docs
  '-----BEGIN [A-Z 0-9-]*PRIVATE KEY-----'     # SSH / RSA / EC / OPENSSH / PGP private key blocks
  'ghp_[A-Za-z0-9]{36}'                        # GitHub personal access token (classic)
  'github_pat_[A-Za-z0-9_]{82}'                # GitHub fine-grained personal access token
  'sk-ant-[A-Za-z0-9_-]{90,}'                  # Anthropic API key
  'sk-[A-Za-z0-9]{48,}'                        # OpenAI API key (legacy and current shapes)
  'xox[bpars]-[A-Za-z0-9-]{10,}'               # Slack tokens
)

DIFF="$(git diff --cached --no-color || true)"
if [ -z "$DIFF" ]; then
  exit 0
fi

for pat in "${PATTERNS[@]}"; do
  if echo "$DIFF" | grep -qE "$pat"; then
    {
      echo "warden hook: secret pattern detected in staged changes"
      echo "  pattern: $pat"
      echo "  action:  commit blocked"
      echo "  hint:    \`git reset HEAD <file>\` then remove the secret before re-staging"
      echo "           if this is a fixture meant to demo secret-detection, use a documented"
      echo "           placeholder (e.g. AKIAIOSFODNN7EXAMPLE) — never a real-looking value."
    } >&2
    exit 2
  fi
done

exit 0
