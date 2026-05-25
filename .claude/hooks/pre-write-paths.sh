#!/usr/bin/env bash
# pre-write-paths.sh
#
# Blocks Write/Edit tool calls targeting paths outside the repo root or
# inside ignored / dangerous directories (node_modules, .git, dist, build).
#
# Defense-in-depth against path-traversal from agent tool calls. The
# repo root is computed from this script's own location, so the hook
# remains correct regardless of the working directory at invocation.
#
# Exit codes:
#   0 — pass
#   2 — block (out-of-tree or protected-dir write)

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

if [ -z "$FILE_PATH" ]; then
  # No file path on this tool call. Defensive: should not happen for Write/Edit.
  exit 0
fi

# Resolve the repo root by walking up from this script's directory.
# This file lives at <repo>/.claude/hooks/pre-write-paths.sh, so the
# repo root is two directories above.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Normalize the file path. realpath -m handles non-existent leaves
# (GNU coreutils); readlink -f is the BSD/macOS-friendly fallback.
NORMALIZED="$(realpath -m "$FILE_PATH" 2>/dev/null \
  || readlink -f "$FILE_PATH" 2>/dev/null \
  || echo "$FILE_PATH")"

# Block paths outside the repo root.
case "$NORMALIZED" in
  "$REPO_ROOT"|"$REPO_ROOT"/*)
    ;;
  *)
    {
      echo "warden hook: write outside repo root blocked"
      echo "  target: $NORMALIZED"
      echo "  repo:   $REPO_ROOT"
    } >&2
    exit 2
    ;;
esac

# Block writes inside protected subdirectories.
for forbidden in \
  "$REPO_ROOT/node_modules" \
  "$REPO_ROOT/.git" \
  "$REPO_ROOT/dist" \
  "$REPO_ROOT/build"
do
  case "$NORMALIZED" in
    "$forbidden"|"$forbidden"/*)
      {
        echo "warden hook: write into protected directory blocked"
        echo "  target:    $NORMALIZED"
        echo "  protected: $forbidden"
      } >&2
      exit 2
      ;;
  esac
done

exit 0
