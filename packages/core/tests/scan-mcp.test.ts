// warden: payload-fixture detector-test -- scan-mcp tests feed malformed and adversarial MCP configs as inputs
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanMcp } from '../src/scan-mcp.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const MCP_FIXTURES = resolve(REPO_ROOT, 'tests/fixtures/mcp');

function readFixture(name: string): string {
  return readFileSync(resolve(MCP_FIXTURES, name, 'mcp.json'), 'utf8');
}

describe('scanMcp — input handling', () => {
  test('empty input -> no findings', () => {
    expect(scanMcp('')).toEqual([]);
  });

  test('invalid JSON -> single mcp.invalid-json finding', () => {
    const out = scanMcp('{not json');
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.invalid-json');
    expect(out[0]?.severity).toBe('high');
  });

  test('non-object root -> single mcp.invalid-json finding', () => {
    const out = scanMcp('[]');
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.invalid-json');
  });

  test('missing mcpServers -> no findings (empty config is valid)', () => {
    expect(scanMcp('{}')).toEqual([]);
  });

  test('mcpServers not an object -> mcp.invalid-json finding', () => {
    const out = scanMcp('{"mcpServers": []}');
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.invalid-json');
  });

  test('server entry not an object -> mcp.invalid-json finding for that server', () => {
    const out = scanMcp('{"mcpServers": {"bad": "string"}}');
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.invalid-json');
    expect(out[0]?.evidence).toContain('bad');
  });
});

describe('scanMcp — minimal-correct fixture passes clean', () => {
  test('zero findings', () => {
    const out = scanMcp(readFixture('minimal-correct'));
    expect(out).toEqual([]);
  });
});

describe('scanMcp — missing-version-pin fixture', () => {
  test('fires mcp.command-not-pinned at medium severity', () => {
    const out = scanMcp(readFixture('missing-version-pin'));
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.command-not-pinned');
    expect(out[0]?.severity).toBe('medium');
    expect(out[0]?.serverName).toBe('floating-version');
    expect(out[0]?.threatIds).toEqual(['T2']);
  });

  test('pinned package does NOT fire (sanity check on the rule)', () => {
    const json = JSON.stringify({
      mcpServers: {
        good: { command: 'npx', args: ['-y', '@scope/pkg@1.2.3'] },
      },
    });
    const out = scanMcp(json);
    expect(out).toEqual([]);
  });

  test('unscoped pinned package does NOT fire', () => {
    const json = JSON.stringify({
      mcpServers: {
        good: { command: 'npx', args: ['cowsay@1.5.0'] },
      },
    });
    const out = scanMcp(json);
    expect(out).toEqual([]);
  });

  test('--package <pkg> form is recognized', () => {
    const json = JSON.stringify({
      mcpServers: {
        bad: { command: 'npx', args: ['--package', '@scope/pkg', '-y'] },
      },
    });
    const out = scanMcp(json);
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.command-not-pinned');
  });
});

describe('scanMcp — absolute-path-untrusted fixture', () => {
  test('fires mcp.absolute-path-untrusted-binary at medium severity', () => {
    const out = scanMcp(readFixture('absolute-path-untrusted'));
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.absolute-path-untrusted-binary');
    expect(out[0]?.severity).toBe('medium');
    expect(out[0]?.serverName).toBe('rogue-binary');
  });

  test('system path /usr/bin/node does NOT fire', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { command: '/usr/bin/node', args: ['/opt/server.js'] } },
    });
    expect(scanMcp(json)).toEqual([]);
  });

  test('bare "node" (PATH lookup) does NOT fire', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { command: 'node', args: ['server.js@1.0.0'] } },
    });
    expect(scanMcp(json)).toEqual([]);
  });

  test('Windows-style absolute outside system prefixes fires', () => {
    const json = JSON.stringify({
      mcpServers: { bad: { command: 'C:\\Users\\alice\\Downloads\\helper.exe', args: [] } },
    });
    const out = scanMcp(json);
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.absolute-path-untrusted-binary');
  });
});

describe('scanMcp — network-egress-tool fixture', () => {
  test('fires mcp.http-transport-external at high severity', () => {
    const out = scanMcp(readFixture('network-egress-tool'));
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.http-transport-external');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.serverName).toBe('remote-fetcher');
  });

  test('localhost HTTP does NOT fire (loopback exempt)', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { type: 'http', url: 'http://localhost:8080/mcp' } },
    });
    expect(scanMcp(json)).toEqual([]);
  });

  test('127.0.0.1 does NOT fire', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { type: 'sse', url: 'http://127.0.0.1:8080/sse' } },
    });
    expect(scanMcp(json)).toEqual([]);
  });

  test('malformed URL is silently ignored (no half-baked finding)', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { type: 'http', url: 'not a url' } },
    });
    expect(scanMcp(json)).toEqual([]);
  });
});

describe('scanMcp — shell-exec-command fixture', () => {
  test('fires mcp.shell-exec-command at high severity', () => {
    const out = scanMcp(readFixture('shell-exec-command'));
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.shell-exec-command');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.serverName).toBe('shell-tunnel');
  });

  test('bash without -c does NOT fire', () => {
    const json = JSON.stringify({
      mcpServers: { ok: { command: '/bin/bash', args: ['/opt/script.sh'] } },
    });
    expect(scanMcp(json)).toEqual([]);
  });

  test('powershell -Command fires', () => {
    const json = JSON.stringify({
      mcpServers: {
        bad: { command: 'powershell.exe', args: ['-Command', 'Get-Process'] },
      },
    });
    const out = scanMcp(json);
    expect(out.length).toBe(1);
    expect(out[0]?.ruleId).toBe('mcp.shell-exec-command');
  });
});

describe('scanMcp — determinism + multi-rule', () => {
  test('multiple servers report in stable name-then-rule order', () => {
    const json = JSON.stringify({
      mcpServers: {
        zeta: { command: 'npx', args: ['@scope/zeta'] },
        alpha: { command: '/home/u/bin/alpha', args: [] },
      },
    });
    const out1 = scanMcp(json);
    const out2 = scanMcp(json);
    expect(out1.map((f) => `${f.serverName}:${f.ruleId}`)).toEqual([
      'alpha:mcp.absolute-path-untrusted-binary',
      'zeta:mcp.command-not-pinned',
    ]);
    expect(out1).toEqual(out2);
  });

  test('one server triggering two rules yields two findings', () => {
    // Absolute-path AND no version pin both fire? Actually the pin rule
    // only triggers on package-runner commands (npx/bunx/etc.), so this
    // server only fires the path rule. Combine path + shell to get two.
    const json = JSON.stringify({
      mcpServers: {
        combo: { command: '/home/u/bash', args: ['-c', 'echo hi'] },
      },
    });
    const out = scanMcp(json);
    const ids = out.map((f) => f.ruleId).sort();
    expect(ids).toEqual(['mcp.absolute-path-untrusted-binary', 'mcp.shell-exec-command']);
  });
});

describe('scanMcp — _warden marker key is stripped before rule eval', () => {
  test('_warden at root is not treated as a server entry', () => {
    const json = JSON.stringify({
      _warden: 'warden: payload-fixture mcp-config -- test',
      mcpServers: {
        ok: { command: 'npx', args: ['@scope/pkg@1.0.0'] },
      },
    });
    expect(scanMcp(json)).toEqual([]);
  });
});
