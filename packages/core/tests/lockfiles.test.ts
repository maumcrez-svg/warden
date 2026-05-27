import { describe, expect, test } from 'bun:test';
import { parseCargoLockfile } from '../src/lockfiles/lockfile-cargo.ts';
import { parseNpmLockfile } from '../src/lockfiles/lockfile-npm.ts';
import { parsePoetryLockfile } from '../src/lockfiles/lockfile-poetry.ts';
import { parseUvLockfile } from '../src/lockfiles/lockfile-uv.ts';

describe('parseNpmLockfile — direct/transitive', () => {
  test('package-lock.json v3 root deps classify as direct, nested as transitive', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { 'event-stream': '3.3.6' },
        },
        'node_modules/event-stream': { version: '3.3.6' },
        'node_modules/flatmap-stream': { version: '0.1.1' },
      },
    });
    const r = parseNpmLockfile(content);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    const event = r.entries.find((e) => e.name === 'event-stream');
    const flatmap = r.entries.find((e) => e.name === 'flatmap-stream');
    expect(event?.position).toBe('direct');
    expect(flatmap?.position).toBe('transitive');
  });

  test('devDependencies count as direct (ADR 0016 §4 — no dev/prod tiering yet)', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { 'some-dev-tool': '1.0.0' } },
        'node_modules/some-dev-tool': { version: '1.0.0' },
      },
    });
    const r = parseNpmLockfile(content);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.entries[0]?.position).toBe('direct');
  });

  test('lockfileVersion 1 → error (deferred per ADR 0016 §1)', () => {
    const content = JSON.stringify({ lockfileVersion: 1 });
    const r = parseNpmLockfile(content);
    expect(r.kind).toBe('error');
  });
});

describe('parseCargoLockfile — direct vs transitive', () => {
  test('with Cargo.toml manifest: direct names classified from [dependencies]', () => {
    const lock = `
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "syn"
version = "1.0.0"
`;
    const manifest = `
[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1"
`;
    const r = parseCargoLockfile(lock, manifest);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    const serde = r.entries.find((e) => e.name === 'serde');
    const syn = r.entries.find((e) => e.name === 'syn');
    expect(serde?.position).toBe('direct');
    expect(syn?.position).toBe('transitive');
  });

  test('Cargo.toml absent → all entries classified as direct (louder fallback)', () => {
    const lock = `
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "syn"
version = "1.0.0"
`;
    const r = parseCargoLockfile(lock, null);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    for (const e of r.entries) expect(e.position).toBe('direct');
  });

  test('dev-dependencies count as direct', () => {
    const lock = `
[[package]]
name = "test-helper"
version = "0.5.0"
`;
    const manifest = `
[package]
name = "myapp"
version = "0.1.0"

[dev-dependencies]
test-helper = "0.5"
`;
    const r = parseCargoLockfile(lock, manifest);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.entries[0]?.position).toBe('direct');
  });
});

describe('parsePoetryLockfile — direct vs transitive', () => {
  test('with pyproject.toml: only deps under [tool.poetry.dependencies] are direct', () => {
    const lock = `
[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.7"

[[package]]
name = "urllib3"
version = "2.0.7"
description = ""
optional = false
python-versions = ">=3.7"
`;
    const manifest = `
[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31"
`;
    const r = parsePoetryLockfile(lock, manifest);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    const requests = r.entries.find((e) => e.name === 'requests');
    const urllib = r.entries.find((e) => e.name === 'urllib3');
    expect(requests?.position).toBe('direct');
    expect(urllib?.position).toBe('transitive');
  });

  test('pyproject.toml absent → all entries direct (ADR 0016 §3 fallback)', () => {
    const lock = `
[[package]]
name = "requests"
version = "2.31.0"
`;
    const r = parsePoetryLockfile(lock, null);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.entries[0]?.position).toBe('direct');
  });
});

describe('parseUvLockfile — direct vs transitive', () => {
  test('uv.lock with virtual project entry: deps named in virtual are direct', () => {
    const lock = `
version = 1

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
`;
    const r = parseUvLockfile(lock);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    // The virtual entry itself is filtered out.
    expect(r.entries.find((e) => e.name === 'my-app')).toBeUndefined();
    expect(r.entries.find((e) => e.name === 'requests')?.position).toBe('direct');
    expect(r.entries.find((e) => e.name === 'urllib3')?.position).toBe('transitive');
  });

  test('uv.lock without virtual entry: all entries direct (older format)', () => {
    const lock = `
version = 1

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
`;
    const r = parseUvLockfile(lock);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.entries[0]?.position).toBe('direct');
  });
});
