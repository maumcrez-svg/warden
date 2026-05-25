// Path-based detection of agent-context file kinds. Pure: takes a
// repo-relative path string, returns a typed FileKind (or null when the
// file is not a scanning candidate).
//
// Recognized kinds:
//   - claude-md             CLAUDE.md (case-sensitive — matches the canonical name)
//   - agents-md             AGENTS.md
//   - cursorrules           .cursorrules
//   - cursor-rule           .cursor/rules/*.mdc
//   - windsurfrules         .windsurfrules
//   - clinerules            .clinerules
//   - aider-conf            .aider.conf.yml
//   - copilot-instructions  .github/copilot-instructions.md
//   - mcp-json              mcp.json
//   - skill-md              .claude/{commands,skills}/**/*.md, **/skills/**/SKILL.md
//   - markdown              fallback for any other *.md or *.mdc not matched above
//
// "markdown" is included because invisible Unicode in any markdown an agent
// might read is the very threat M1 addresses. ADR 0006 §"Generic-markdown
// fallback" records why we cast the net at .md/.mdc rather than only the
// named files.

export type FileKind =
  | 'claude-md'
  | 'agents-md'
  | 'cursorrules'
  | 'cursor-rule'
  | 'windsurfrules'
  | 'clinerules'
  | 'aider-conf'
  | 'copilot-instructions'
  | 'mcp-json'
  | 'skill-md'
  | 'markdown';

const CURSOR_RULE = /(^|\/)\.cursor\/rules\/[^/]+\.mdc$/;
const COPILOT = /(^|\/)\.github\/copilot-instructions\.md$/;
const CLAUDE_COMMAND = /(^|\/)\.claude\/commands\/[^/]+\.md$/;
const CLAUDE_SKILL = /(^|\/)\.claude\/skills\/[^/]+\/SKILL\.md$/;
const NAMED_SKILL = /(^|\/)skills\/[^/]+\/SKILL\.md$/;
const SKILL_NAMED = /(^|\/)SKILL\.md$/;
// .mdc is Cursor's "Markdown with frontmatter" rule format; outside
// .cursor/rules/ it is still overwhelmingly Cursor-related, so treat
// it as cursor-rule rather than generic markdown.
const MDC = /\.mdc$/i;
const MARKDOWN = /\.(md|markdown)$/i;

export function detectFormat(relPath: string): FileKind | null {
  const norm = relPath.replaceAll('\\', '/');
  const base = norm.split('/').pop() ?? '';

  switch (base) {
    case 'CLAUDE.md':
      return 'claude-md';
    case 'AGENTS.md':
      return 'agents-md';
    case '.cursorrules':
      return 'cursorrules';
    case '.windsurfrules':
      return 'windsurfrules';
    case '.clinerules':
      return 'clinerules';
    case '.aider.conf.yml':
      return 'aider-conf';
    case 'mcp.json':
      return 'mcp-json';
  }

  if (CURSOR_RULE.test(norm)) return 'cursor-rule';
  if (COPILOT.test(norm)) return 'copilot-instructions';
  if (CLAUDE_COMMAND.test(norm)) return 'skill-md';
  if (CLAUDE_SKILL.test(norm)) return 'skill-md';
  if (NAMED_SKILL.test(norm)) return 'skill-md';
  if (SKILL_NAMED.test(norm)) return 'skill-md';

  if (MDC.test(base)) return 'cursor-rule';
  if (MARKDOWN.test(base)) return 'markdown';

  return null;
}
