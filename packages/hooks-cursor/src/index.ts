// Public surface of @warden-sh/hooks-cursor. Imported by the CLI
// (`warden hooks install cursor`, `warden hooks run cursor`) and by
// unit tests in this package.

export type {
  CursorHookInput,
  CursorBeforeReadFileInput,
  CursorBeforeShellExecutionInput,
  CursorBeforeMCPExecutionInput,
  Decision,
  EvaluateContext,
} from './interceptor.ts';
export { evaluateCursorToolCall } from './interceptor.ts';
export type { InstallOptions, InstallResult } from './install.ts';
export { installCursorHook, mergeHooksFile } from './install.ts';
export type { RunOptions, RunResult } from './run.ts';
export { readAll, runOnInput } from './run.ts';

// Allow this module to be invoked directly as the runtime hook (`bun
// run packages/hooks-cursor/src/index.ts < input.json`). The CLI's
// `warden hooks run cursor` re-uses runOnInput; this entry point
// exists so an installer-free use (or a debug invocation) still works.
if (import.meta.main) {
  const { runOnInput, readAll } = await import('./run.ts');
  const input = await readAll(process.stdin);
  const result = runOnInput(input, { stdout: process.stdout, stderr: process.stderr });
  process.exit(result.exitCode);
}
