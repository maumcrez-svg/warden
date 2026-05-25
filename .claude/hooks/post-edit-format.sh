#!/usr/bin/env bash
# post-edit-format.sh
#
# Auto-formats edited files using Biome. Runs after Write/Edit tool calls.
# Silent on success, prints to stderr on failure. This hook never blocks —
# formatting failure should not abort the agent's flow.
#
# Exit codes:
#   0 — always (non-blocking by design)

set -euo pipefail

INPUT="$(cat)"

if command -v jq >/dev/null 2>&1; then
  FILE_PATH="$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')"
else
  FILE_PATH="$(echo "$INPUT" \
    | grep -oE '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed -E 's/^"file_path"[[:space:]]*:[[:space:]]*"(.*)"$/\1/' \
    | head -n1)"
fi

# No-op if we cannot resolve a file or it does not exist.
if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Only format languages Biome handles.
case "$FILE_PATH" in
  *.ts|*.tsx|*.js|*.jsx|*.cjs|*.mjs|*.json|*.jsonc)
    ;;
  *)
    exit 0
    ;;
esac

# Skip silently if bunx is unavailable (this is a post-hook; missing dev
# tools should not break the agent flow).
if ! command -v bunx >/dev/null 2>&1; then
  exit 0
fi

bunx biome format --write "$FILE_PATH" >/dev/null 2>&1 || {
  echo "warden hook: biome format failed on $FILE_PATH (non-blocking)" >&2
}

exit 0
