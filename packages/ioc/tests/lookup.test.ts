import { describe, expect, test } from 'bun:test';
import { INDEX_SCHEMA, type Index } from '../src/index-store.ts';
import { lookupInIndex, parseLookupTarget } from '../src/lookup.ts';

function withSingleAdvisory(
  packageName: string,
  introduced: string,
  fixed: string | undefined,
): Index {
  return {
    schema: INDEX_SCHEMA,
    ecosystem: 'npm',
    source: 'osv',
    synced_at: 't',
    advisory_count: 1,
    packages: {
      [packageName]: [
        {
          id: 'GHSA-test',
          severity: 'high',
          summary: 'fixture',
          ranges: [
            {
              type: 'SEMVER',
              events: fixed === undefined ? [{ introduced }] : [{ introduced }, { fixed }],
            },
          ],
          references: [],
        },
      ],
    },
  };
}

describe('parseLookupTarget', () => {
  test('parses ecosystem:package@version', () => {
    const t = parseLookupTarget('npm:event-stream@3.3.6');
    expect(t).toEqual({ ecosystem: 'npm', packageName: 'event-stream', version: '3.3.6' });
  });

  test('handles scoped npm packages with @ in name', () => {
    const t = parseLookupTarget('npm:@scope/pkg@1.0.0');
    expect(t).toEqual({ ecosystem: 'npm', packageName: '@scope/pkg', version: '1.0.0' });
  });

  test('returns null on malformed input', () => {
    expect(parseLookupTarget('no-colon')).toBeNull();
    expect(parseLookupTarget('npm:pkg')).toBeNull();
    expect(parseLookupTarget('npm:@1.0.0')).toBeNull();
  });
});

describe('lookupInIndex — match cases', () => {
  test('returns the matching advisory when version is in range', () => {
    const idx = withSingleAdvisory('event-stream', '3.3.6', '4.0.0');
    const r = lookupInIndex(idx, {
      ecosystem: 'npm',
      packageName: 'event-stream',
      version: '3.3.6',
    });
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0]?.advisory.id).toBe('GHSA-test');
    expect(r.matches[0]?.confidence).toBe('in-range');
  });

  test('returns empty array when version is out of range', () => {
    const idx = withSingleAdvisory('event-stream', '3.3.6', '4.0.0');
    const r = lookupInIndex(idx, {
      ecosystem: 'npm',
      packageName: 'event-stream',
      version: '4.0.0',
    });
    expect(r.matches).toHaveLength(0);
  });

  test('returns empty array when package is not in the index', () => {
    const idx = withSingleAdvisory('event-stream', '3.3.6', '4.0.0');
    const r = lookupInIndex(idx, {
      ecosystem: 'npm',
      packageName: 'react',
      version: '18.0.0',
    });
    expect(r.matches).toHaveLength(0);
  });
});

describe('lookupInIndex — version-unknown confidence', () => {
  test('returns version-unknown for non-parseable target version', () => {
    const idx = withSingleAdvisory('foo', '0', undefined);
    const r = lookupInIndex(idx, {
      ecosystem: 'npm',
      packageName: 'foo',
      version: 'not-a-version',
    });
    expect(r.matches[0]?.confidence).toBe('version-unknown');
  });

  test('returns version-unknown for GIT-type ranges', () => {
    const idx: Index = {
      schema: INDEX_SCHEMA,
      ecosystem: 'npm',
      source: 'osv',
      synced_at: 't',
      advisory_count: 1,
      packages: {
        foo: [
          {
            id: 'GHSA-git',
            severity: 'medium',
            summary: 's',
            ranges: [{ type: 'GIT', events: [{ introduced: 'abc1234' }] }],
            references: [],
          },
        ],
      },
    };
    const r = lookupInIndex(idx, { ecosystem: 'npm', packageName: 'foo', version: '1.0.0' });
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0]?.confidence).toBe('version-unknown');
    expect(r.matches[0]?.note).toContain('GIT');
  });
});
