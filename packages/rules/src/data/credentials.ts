// warden: payload-fixture rules-data -- credential paths and shell verbs are attack-shaped by definition (ADR 0010)
//
// Credential blocklist for the M6 PreToolUse hook adapter
// (packages/hooks-claude). Each rule cites threat T5 (agent-tool
// credential exfiltration; see docs/THREAT_MODEL.md).
//
// Design constraints (ADR 0013 §5):
//   - Pure data + pure predicates. No filesystem access, no I/O.
//   - Public-half files (`.pub`, SSH `config`, `known_hosts`, `*.example`,
//     `*.sample`) are explicit allow-overrides — they're read all the time
//     legitimately and blocking them would degrade the developer UX.
//   - Shell-pattern coverage is intentionally narrow: the file-path rule
//     already covers the Read tool, so the shell rule only needs to handle
//     the case where the agent shells out instead of using Read directly.
//
// Severity policy: all three rules are HIGH. A credential-file read or
// shell exfil through an AI agent is never accidental in a hot-path
// developer workflow; reviewers see exactly the rules that fire.

import type { UnicodeSeverity } from './unicode-ranges.ts';

export type CredentialSeverity = UnicodeSeverity;

export type CredentialRuleHit = {
  readonly evidence: string;
};

// Tokenized view of a Claude Code tool call. Built by the hooks-claude
// runtime from the stdin JSON; rules see only the normalized shape so
// they stay vendor-independent (Cursor / Cline adapters will reuse this
// rule pack against their own input parsers).
export type ToolCallView = {
  readonly tool: 'read' | 'edit' | 'write' | 'bash' | 'other';
  // Canonicalized absolute path (~ expanded to the supplied home dir).
  // Empty string when the tool is not a file-path tool.
  readonly absPath: string;
  // Original raw path/command as the agent submitted it. Used for
  // evidence strings so reviewers see what the agent actually asked
  // for, not the normalized form.
  readonly raw: string;
  // Tokenized command words for Bash. Empty for non-Bash tools.
  readonly commandTokens: ReadonlyArray<string>;
};

export type CredentialRule = {
  readonly id: string;
  readonly threatIds: ReadonlyArray<'T5'>;
  readonly name: string;
  readonly severity: CredentialSeverity;
  readonly citation: string;
  readonly verifiedDate: string;
  readonly evaluate: (call: ToolCallView) => ReadonlyArray<CredentialRuleHit>;
};

// Path globs (POSIX-style; backslash paths are normalized to forward
// slashes upstream). `**` matches zero or more directory segments, `*`
// matches one segment without `/`. The matcher is hand-rolled to avoid
// a dependency on a glob library on the hot path.
//
// Citation for the credential path set:
//   - SSH manpages, AWS CLI docs, GPG docs (canonical credential
//     locations per their respective vendors).
//   - OWASP LLM02:2025 Sensitive Information Disclosure —
//     https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/
//   - TrapDoor (T1, Socket May 2026) and GlassWorm (T2) — both attack
//     chains targeted exactly these paths.
const CREDENTIAL_DENY_GLOBS: ReadonlyArray<string> = [
  // SSH private keys. We cover the common id_* names + the *_rsa /
  // *_ed25519 / *_ecdsa suffix family. The .pub allow-glob below means
  // public halves pass through.
  '**/.ssh/id_rsa',
  '**/.ssh/id_dsa',
  '**/.ssh/id_ecdsa',
  '**/.ssh/id_ed25519',
  '**/.ssh/id_ed25519_sk',
  '**/.ssh/id_ecdsa_sk',
  '**/.ssh/*_rsa',
  '**/.ssh/*_dsa',
  '**/.ssh/*_ecdsa',
  '**/.ssh/*_ed25519',
  '**/.ssh/identity',
  // AWS CLI credentials and config — both contain the access key /
  // secret access key in the standard layout.
  '**/.aws/credentials',
  '**/.aws/config',
  // Project-local environment files. The carve-outs (.example,
  // .sample) live in CREDENTIAL_ALLOW_GLOBS below.
  '**/.env',
  '**/.env.*',
  // GPG private keyring (both the modern per-key layout and the
  // legacy secring.gpg).
  '**/.gnupg/private-keys-v1.d/**',
  '**/.gnupg/secring.gpg',
  // Crypto wallets and mnemonic dumps.
  '**/wallet.json',
  '**/*.wallet',
  '**/mnemonic',
  '**/mnemonic.txt',
  '**/mnemonic.json',
  '**/seed.txt',
  // kubectl / docker / npm / pip / gh / heroku credential stores.
  // These are documented credential paths from each vendor's CLI
  // (kubectl manpage, `docker login`, `~/.npmrc` auth tokens,
  // `~/.pypirc`, `gh auth login`, Heroku CLI). The .pub / .example /
  // .sample allow-overrides apply here too.
  '**/.kube/config',
  '**/.docker/config.json',
  '**/.npmrc',
  '**/.pypirc',
  '**/.netrc',
];

const CREDENTIAL_ALLOW_GLOBS: ReadonlyArray<string> = [
  // Public halves and SSH housekeeping files.
  '**/*.pub',
  '**/.ssh/config',
  '**/.ssh/known_hosts',
  '**/.ssh/known_hosts.old',
  '**/.ssh/authorized_keys',
  // Documentation / template files. `.env.example` and `.env.sample`
  // are the de facto onboarding convention; `.npmrc.example` etc.
  // follow the same shape.
  '**/*.example',
  '**/*.sample',
  '**/*.template',
];

// Shell binaries that, when invoked against a credential path, are
// strong evidence of an exfiltration attempt. Listed as data rather
// than baked into the regex so the audit trail is one-stop.
const SHELL_READ_VERBS = new Set<string>([
  'cat',
  'less',
  'more',
  'head',
  'tail',
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'od',
  'hexdump',
  'xxd',
  'strings',
  'base64',
  'openssl',
  'gpg',
]);

// Network-egress verbs. When any of these appear in a command that
// also references a credential path, the credential-pipe-network rule
// fires regardless of how the path is referenced (cat | curl, openssl |
// nc, curl --upload-file …).
const NETWORK_EGRESS_VERBS = new Set<string>([
  'curl',
  'wget',
  'scp',
  'rsync',
  'sftp',
  'ftp',
  'nc',
  'ncat',
  'socat',
  'http',
  'httpie',
]);

function matchGlob(pattern: string, path: string): boolean {
  // Hand-rolled glob → regex translator. `**/` at the start of a
  // segment matches zero or more directory segments (so `**/.env`
  // matches both `.env` and `/a/b/.env`). Bare `**` matches any
  // character including `/`. `*` matches any non-`/` character;
  // `?` matches any single non-`/` character. Other regex
  // metacharacters are escaped.
  let regex = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === '*' && pattern[i + 1] === '*' && pattern[i + 2] === '/') {
      regex += '(?:.*/)?';
      i += 2;
      continue;
    }
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        regex += '.*';
        i++;
      } else {
        regex += '[^/]*';
      }
      continue;
    }
    if (ch === '?') {
      regex += '[^/]';
      continue;
    }
    if (/[\\.+^$(){}|[\]]/.test(ch)) {
      regex += `\\${ch}`;
      continue;
    }
    regex += ch;
  }
  regex += '$';
  return new RegExp(regex).test(path);
}

export function pathMatchesCredentialBlocklist(absPath: string): boolean {
  for (const allow of CREDENTIAL_ALLOW_GLOBS) {
    if (matchGlob(allow, absPath)) return false;
  }
  for (const deny of CREDENTIAL_DENY_GLOBS) {
    if (matchGlob(deny, absPath)) return true;
  }
  return false;
}

// Find the credential path (if any) referenced anywhere in the
// command-token stream. Returns the first match. Tokens are checked
// individually so `cat ~/.ssh/id_rsa` and `openssl rsa -in ~/.ssh/id_rsa`
// both surface. The home-expansion is done upstream by the runtime, so
// tokens here are already absolute when they came from `~/...`.
function findCredentialTokenIndex(tokens: ReadonlyArray<string>): number {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i] as string;
    if (pathMatchesCredentialBlocklist(t)) return i;
  }
  return -1;
}

function commandBaseName(token: string): string {
  const slash = token.lastIndexOf('/');
  const base = slash === -1 ? token : token.slice(slash + 1);
  return base.toLowerCase();
}

function anyTokenIsBase(tokens: ReadonlyArray<string>, set: Set<string>): boolean {
  for (const t of tokens) {
    if (set.has(commandBaseName(t))) return true;
  }
  return false;
}

export const CREDENTIAL_RULES: ReadonlyArray<CredentialRule> = [
  {
    id: 'hooks.credential-file-read',
    threatIds: ['T5'],
    name: 'Tool call reads a credential file',
    severity: 'high',
    citation:
      'OWASP LLM02:2025 Sensitive Information Disclosure — https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/ ; TrapDoor (Socket, May 2026) and GlassWorm reports both terminated in credential-file exfiltration via agent tool calls.',
    verifiedDate: '2026-05-25',
    evaluate: (call) => {
      if (call.tool !== 'read' && call.tool !== 'edit' && call.tool !== 'write') return [];
      if (!pathMatchesCredentialBlocklist(call.absPath)) return [];
      return [{ evidence: `${call.tool} ${call.raw} (matches credential path blocklist)` }];
    },
  },
  {
    id: 'hooks.credential-shell-read',
    threatIds: ['T5'],
    name: 'Bash command reads a credential file with a shell-read verb',
    severity: 'high',
    citation:
      'OWASP LLM02:2025 Sensitive Information Disclosure (link above). Shell-read verbs documented in their respective manpages (cat(1), openssl(1), base64(1), gpg(1)).',
    verifiedDate: '2026-05-25',
    evaluate: (call) => {
      if (call.tool !== 'bash') return [];
      const credIdx = findCredentialTokenIndex(call.commandTokens);
      if (credIdx === -1) return [];
      if (!anyTokenIsBase(call.commandTokens, SHELL_READ_VERBS)) return [];
      const credToken = call.commandTokens[credIdx] as string;
      return [{ evidence: `bash command reads ${credToken} via shell-read verb` }];
    },
  },
  {
    id: 'hooks.credential-pipe-network',
    threatIds: ['T5'],
    name: 'Bash command references a credential file alongside a network-egress verb',
    severity: 'high',
    citation:
      'OWASP LLM02:2025 Sensitive Information Disclosure (link above); TrapDoor and GlassWorm attack chains used `curl`/`wget`/`scp` to ship credential file contents off the host.',
    verifiedDate: '2026-05-25',
    evaluate: (call) => {
      if (call.tool !== 'bash') return [];
      const credIdx = findCredentialTokenIndex(call.commandTokens);
      if (credIdx === -1) return [];
      if (!anyTokenIsBase(call.commandTokens, NETWORK_EGRESS_VERBS)) return [];
      const credToken = call.commandTokens[credIdx] as string;
      return [{ evidence: `bash command references ${credToken} with a network-egress verb` }];
    },
  },
];
