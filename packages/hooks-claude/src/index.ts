// Public surface of @warden-sh/hooks-claude. Imported by the CLI
// (`warden hooks install claude`, `warden hooks run claude`) and by
// unit tests in this package.

export type { Allowlist, AllowEntry, AllowlistParseResult } from './allowlist.ts';
export { ALLOWLIST_SCHEMA, emptyAllowlist, parseAllowlist } from './allowlist.ts';
export type { ClaudeToolUseInput, Decision, EvaluateContext } from './interceptor.ts';
export { evaluateToolCall, pathMatchesCredentialBlocklist } from './interceptor.ts';
export type { InstallOptions, InstallResult } from './install.ts';
export { installClaudeHook, mergeSettings } from './install.ts';
export type { RunOptions, RunResult } from './run.ts';
export { readAll, runOnInput } from './run.ts';

// Allow this module to be invoked directly as the runtime hook (`bun
// run packages/hooks-claude/src/index.ts < input.json`). The CLI's
// `warden hooks run claude` re-uses runOnInput; this entry point
// exists so an installer-free use (or a debug invocation) still works.
if (import.meta.main) {
  const { runOnInput, readAll } = await import('./run.ts');
  const input = await readAll(process.stdin);
  const result = runOnInput(input, { stdout: process.stdout, stderr: process.stderr });
  process.exit(result.exitCode);
}
