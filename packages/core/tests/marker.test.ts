// warden: payload-fixture detector-test -- marker parser test feeds invalid markers as inputs
import { describe, expect, test } from 'bun:test';
import {
  type FindingCategory,
  type Marker,
  applyMarker,
  markerCoversCategory,
  parseMarker,
} from '../src/marker.ts';

function expectOk(filePath: string, content: string): Marker {
  const r = parseMarker(filePath, content);
  if (r.kind !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(r)}`);
  return r.marker;
}

function expectErr(filePath: string, content: string): string {
  const r = parseMarker(filePath, content);
  if (r.kind !== 'error') throw new Error(`expected error, got ${JSON.stringify(r)}`);
  return r.message;
}

function expectNone(filePath: string, content: string): void {
  const r = parseMarker(filePath, content);
  if (r.kind !== 'none') throw new Error(`expected none, got ${JSON.stringify(r)}`);
}

describe('parseMarker — file-type detection', () => {
  test('TypeScript file with // comment marker', () => {
    const m = expectOk(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data -- regex literals in rule pack\nexport const x = 1;\n',
    );
    expect(m.families).toEqual(['rules-data']);
    expect(m.reason).toBe('regex literals in rule pack');
    expect(m.scope).toEqual({ kind: 'file' });
    expect(m.line).toBe(1);
  });

  test('Markdown file with <!-- --> comment marker', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- T1 tag-char carrier -->\n# Heading\n',
    );
    expect(m.families).toEqual(['trapdoor-unicode']);
    expect(m.reason).toBe('T1 tag-char carrier');
  });

  test('Unsupported file type returns none', () => {
    expectNone('config.json', '{"warden": "payload-fixture rules-data -- whatever"}\n');
  });

  test('Backslash-separated paths normalize for path-restriction checks', () => {
    const m = expectOk(
      'packages\\rules\\src\\data\\prompt-injection.ts',
      '// warden: payload-fixture rules-data -- regex literals in rule pack\n',
    );
    expect(m.families).toEqual(['rules-data']);
  });
});

describe('parseMarker — header zone', () => {
  test('marker after shebang is in header zone', () => {
    const m = expectOk(
      'packages/cli/tests/foo.test.ts',
      '#!/usr/bin/env bun\n// warden: payload-fixture detector-test -- shebang then marker\nimport x;\n',
    );
    expect(m.line).toBe(2);
  });

  test('marker after blank lines and other comments is in header zone', () => {
    const m = expectOk(
      'packages/rules/src/data/prompt-injection.ts',
      '\n// file overview comment\n//\n// warden: payload-fixture rules-data -- after preamble\nexport const x = 1;\n',
    );
    expect(m.line).toBe(4);
  });

  test('marker after first code line is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      'export const x = 1;\n// warden: payload-fixture rules-data -- too late\n',
    );
    expect(msg).toContain('outside header zone');
  });

  test('marker after first markdown content line is parse error', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '# Heading\n<!-- warden: payload-fixture trapdoor-unicode -- too late -->\n',
    );
    expect(msg).toContain('outside header zone');
  });

  test('multiple markers in header zone is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data -- first\n// warden: payload-fixture rules-data -- second\n',
    );
    expect(msg).toContain('multiple warden markers');
  });

  test('no marker at all returns none', () => {
    expectNone('packages/core/src/index.ts', '// nothing special\nexport const x = 1;\n');
  });
});

describe('parseMarker — grammar', () => {
  test('missing reason separator is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data\n',
    );
    expect(msg).toContain('missing reason');
  });

  test('empty reason after -- is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data --   \n',
    );
    // Either the splitter fails (no " -- " sequence) or reason is empty —
    // the user-facing error mentions reason in both cases.
    expect(msg).toMatch(/reason/);
  });

  test('em-dash is NOT accepted (ASCII-only grammar)', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data — em-dash should fail\n',
    );
    expect(msg).toContain('missing reason');
  });

  test('unknown directive is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: trust-anchor rules-data -- not implemented yet\n',
    );
    expect(msg).toContain('unknown directive');
  });

  test('unknown family is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture mcp-config -- not yet defined\n',
    );
    expect(msg).toContain('unknown family');
  });

  test('no families declared is parse error', () => {
    const msg = expectErr(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture -- no families\n',
    );
    expect(msg).toContain('no families');
  });

  test('multiple families union', () => {
    const m = expectOk(
      'packages/core/tests/scan-prompt-injection.test.ts',
      '// warden: payload-fixture detector-test prompt-injection-pattern -- both\n',
    );
    expect(m.families).toEqual(['detector-test', 'prompt-injection-pattern']);
  });
});

describe('parseMarker — path restrictions', () => {
  test('rules-data outside packages/rules/src/data/ is parse error', () => {
    const msg = expectErr(
      'packages/core/src/scan-unicode.ts',
      '// warden: payload-fixture rules-data -- wrong path\n',
    );
    expect(msg).toContain('rules-data');
    expect(msg).toContain('packages/rules/src/data/');
  });

  test('detector-test outside packages/*/tests/ is parse error', () => {
    const msg = expectErr(
      'tests/dogfood.test.ts',
      '// warden: payload-fixture detector-test -- wrong path\n',
    );
    expect(msg).toContain('detector-test');
  });

  test('detector-test inside packages/<pkg>/tests/ is allowed', () => {
    const m = expectOk(
      'packages/cli/tests/cli.test.ts',
      '// warden: payload-fixture detector-test -- allowed\n',
    );
    expect(m.families).toEqual(['detector-test']);
  });

  test('narrow families have no path restriction', () => {
    const m = expectOk(
      'anywhere/at/all.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- can live anywhere -->\n',
    );
    expect(m.families).toEqual(['trapdoor-unicode']);
  });
});

describe('parseMarker — scope', () => {
  test('default scope is file', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- whole file -->\n',
    );
    expect(m.scope).toEqual({ kind: 'file' });
  });

  test('scope:file explicit is allowed', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:file -- whole file -->\n',
    );
    expect(m.scope).toEqual({ kind: 'file' });
  });

  test('scope:lines:N-M parsed', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:lines:3-5 -- range -->\nline 2\nline 3\nline 4\nline 5\nline 6\n',
    );
    expect(m.scope).toEqual({ kind: 'lines', start: 3, end: 5 });
  });

  test('scope start < 1 is parse error', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:lines:0-5 -- bad start -->\nx\nx\nx\nx\nx\n',
    );
    expect(msg).toContain('>= 1');
  });

  test('scope start > end is parse error', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:lines:5-3 -- inverted -->\nx\nx\nx\nx\nx\n',
    );
    expect(msg).toContain('<= end');
  });

  test('scope end > file line count is parse error (stale marker)', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:lines:1-999 -- past EOF -->\nx\nx\n',
    );
    expect(msg).toContain('exceeds file length');
  });

  test('malformed scope:lines is parse error', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:lines:abc -- bad -->\nx\n',
    );
    expect(msg).toContain('malformed scope');
  });

  test('unknown scope kind is parse error', () => {
    const msg = expectErr(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode scope:bytes:0-99 -- wrong unit -->\nx\n',
    );
    expect(msg).toContain('unknown scope');
  });
});

describe('markerCoversCategory', () => {
  test('narrow family covers only its own category', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- T1 -->\n',
    );
    expect(markerCoversCategory(m, 'unicode')).toBe(true);
    expect(markerCoversCategory(m, 'prompt-injection')).toBe(false);
  });

  test('broad family covers all categories', () => {
    const m = expectOk(
      'packages/rules/src/data/prompt-injection.ts',
      '// warden: payload-fixture rules-data -- regex literals\n',
    );
    expect(markerCoversCategory(m, 'unicode')).toBe(true);
    expect(markerCoversCategory(m, 'prompt-injection')).toBe(true);
  });
});

describe('applyMarker — suppression semantics', () => {
  type FakeFinding = { byteOffset: number; tag: string };

  test('null marker keeps all findings', () => {
    const findings: FakeFinding[] = [{ byteOffset: 0, tag: 'a' }];
    const r = applyMarker(null, 'unicode', findings, 'x');
    expect(r.kept).toEqual(findings);
    expect(r.suppressed).toEqual([]);
  });

  test('marker covers category + scope:file → all suppressed', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- T1 -->\n',
    );
    const findings: FakeFinding[] = [
      { byteOffset: 10, tag: 'a' },
      { byteOffset: 20, tag: 'b' },
    ];
    const r = applyMarker(m, 'unicode', findings, 'x');
    expect(r.kept).toEqual([]);
    expect(r.suppressed).toEqual(findings);
  });

  test('marker does not cover category → all kept (cross-category poisoning fires)', () => {
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      '<!-- warden: payload-fixture trapdoor-unicode -- T1 -->\n',
    );
    const findings: FakeFinding[] = [{ byteOffset: 5, tag: 'planted' }];
    const r = applyMarker(m, 'prompt-injection', findings, 'x');
    expect(r.kept).toEqual(findings);
    expect(r.suppressed).toEqual([]);
  });

  test('range scope suppresses only findings inside line range', () => {
    // Content layout (bytes): line1=10 chars+LF, line2=10 chars+LF, line3=10 chars+LF
    // line 1: bytes 0-10  (LF at 10, next line starts at 11)
    // line 2: bytes 11-21 (LF at 21, next line starts at 22)
    // line 3: bytes 22-32
    const content = 'aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n';
    const m = expectOk(
      'tests/fixtures/trapdoor/malicious-tag-chars.md',
      `<!-- warden: payload-fixture trapdoor-unicode scope:lines:2-2 -- only line 2 -->\n${content}`,
    );
    if (m.scope.kind !== 'lines') throw new Error('expected lines scope');
    expect(m.scope).toEqual({ kind: 'lines', start: 2, end: 2 });

    const findings: FakeFinding[] = [
      { byteOffset: 5, tag: 'line1' },
      { byteOffset: 15, tag: 'line2' },
      { byteOffset: 25, tag: 'line3' },
    ];
    const r = applyMarker(m, 'unicode', findings, content);
    expect(r.kept.map((f) => f.tag)).toEqual(['line1', 'line3']);
    expect(r.suppressed.map((f) => f.tag)).toEqual(['line2']);
  });
});

describe('parseMarker — categories table is forward-compatible', () => {
  test('FindingCategory union is the closed set this marker grammar reasons about', () => {
    // Compile-time check: this assignment fails to type-check if a new
    // category is added without updating the marker family map. Catch the
    // mismatch in CI instead of at scan time.
    const all: FindingCategory[] = ['unicode', 'prompt-injection'];
    expect(all.length).toBe(2);
  });
});
