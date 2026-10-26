#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vitest = join(root, 'node_modules', '.bin', 'vitest');

const mutations = [
  {
    name: 'level buckets stop carrying the declared bounded capacity',
    file: 'src/hierarchical/client.ts',
    from: '      bucketSize: capacity,',
    to: '      bucketSize: 1,',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'fixes N=16 and exposes the deliberately overprovisioned level geometry',
  },
  {
    name: 'HMAC placement collapses every lookup to bucket zero',
    file: 'src/hierarchical/client.ts',
    from: '  return word & (bucketCount - 1);',
    to: '  return word * 0;',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'maps an RFC 4231 HMAC-SHA-256 vector without modulo bias',
  },
  {
    name: 'a hashed level silently reuses its previous placement key',
    file: 'src/hierarchical/client.ts',
    from: '  if (level > 0) state.hashKey = await freshHashKey(client);',
    to: '  if (level > 0 && state.hashKey === null) state.hashKey = await freshHashKey(client);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'rotates a hashed level key whenever that level is rebuilt',
  },
  {
    name: 'post-hit lookups keep using the real label instead of a dummy',
    file: 'src/hierarchical/client.ts',
    from: "      const kind: ProbeKind = level === 0 ? 'cache' : found === null ? 'real' : 'dummy';",
    to: "      const kind: ProbeKind = level === 0 ? 'cache' : 'real';",
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'probes every level, then uses a unique dummy probe after a cache hit',
  },
  {
    name: 'the fixed policy stops probing after an early hit',
    file: 'src/hierarchical/client.ts',
    from: "      if (policy === 'skip-after-hit' && found !== null && level > 0) break;",
    to: "      if (policy === 'all-levels' && found !== null && level > 0) break;",
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'probes every level, then uses a unique dummy probe after a cache hit',
  },
  {
    name: 'dummy labels drop the per-access uniqueness component',
    file: 'src/hierarchical/client.ts',
    from: '  new DataView(label.buffer).setUint32(1, accessNumber, false);',
    to: '  new DataView(label.buffer).setUint32(1, accessNumber * 0, false);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'changes a later-level dummy lookup on each access within one key epoch',
  },
  {
    name: 'the dummy-label counter is allowed to wrap once',
    file: 'src/hierarchical/client.ts',
    from: '    if (client.accessCount >= MAX_ACCESS_NUMBER) {',
    to: '    if (client.accessCount > MAX_ACCESS_NUMBER) {',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'refuses before the 32-bit dummy-label counter can wrap or issue traffic',
  },
  {
    name: 'a found copy is left behind before reinsertion',
    file: 'src/hierarchical/client.ts',
    from: '          decoded[slot] = null;',
    to: '          decoded[slot] = clonePlain(item);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'executes the binary-carry rebuild cadence and records real traffic spikes',
  },
  {
    name: 'empty levels are incorrectly marked occupied',
    file: 'src/hierarchical/client.ts',
    from: '  state.occupied = blocks.length > 0;',
    to: '  state.occupied = blocks.length >= 0;',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'executes the binary-carry rebuild cadence and records real traffic spikes',
  },
  {
    name: 'Path traffic counts buckets as if each held only one slot',
    file: 'src/hierarchical/comparison.ts',
    from: '  const readSlots = (after.totalReads - before.totalReads) * Z;',
    to: '  const readSlots = after.totalReads - before.totalReads;',
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'derives both cost traces from real executions and verifies the full logical state',
  },
  {
    name: 'the ordinary comparison secretly uses the skipped-probe policy',
    file: 'src/hierarchical/comparison.ts',
    from: '      const hierarchyReadResult = await hierarchicalRead(hierarchy, item.blockId);',
    to: "      const hierarchyReadResult = await hierarchicalRead(hierarchy, item.blockId, 'skip-after-hit');",
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'derives both cost traces from real executions and verifies the full logical state',
  },
  {
    name: 'the negative control stops running the insecure policy',
    file: 'src/hierarchical/comparison.ts',
    from: "  const skippedRepeat = await hierarchicalRead(skipped, blockId, 'skip-after-hit');",
    to: '  const skippedRepeat = await hierarchicalRead(skipped, blockId);',
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'shows that skipping post-hit probes leaks depth despite returning the same data',
  },
];

const touched = [...new Set(mutations.map((mutation) => join(root, mutation.file)))];
const originals = new Map(touched.map((file) => [file, readFileSync(file)]));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(args) {
  return spawnSync(vitest, args, { cwd: root, encoding: 'utf8', stdio: 'pipe' });
}

function restoreAll() {
  for (const [file, bytes] of originals) writeFileSync(file, bytes);
}

function assertRestored() {
  for (const [file, bytes] of originals) {
    if (digest(readFileSync(file)) !== digest(bytes)) {
      throw new Error(`${relative(root, file)} was not restored byte for byte`);
    }
  }
}

let caught = 0;
try {
  const specs = [...new Set(mutations.map((mutation) => mutation.spec))];
  const baseline = run(['run', ...specs]);
  if (baseline.status !== 0) {
    process.stderr.write(baseline.stdout);
    process.stderr.write(baseline.stderr);
    throw new Error('baseline: unmutated copy FAILED; mutation results below would be meaningless');
  }
  console.log('baseline: unmutated copy PASSES');

  for (const mutation of mutations) {
    const file = join(root, mutation.file);
    const before = readFileSync(file, 'utf8');
    const occurrences = before.split(mutation.from).length - 1;
    if (occurrences !== 1) {
      throw new Error(`${mutation.name}: expected one source anchor, found ${occurrences}`);
    }
    writeFileSync(file, before.replace(mutation.from, mutation.to));
    const result = run(['run', mutation.spec, '-t', mutation.test]);
    writeFileSync(file, originals.get(file));
    if (result.status === 0) {
      process.stderr.write(result.stdout);
      process.stderr.write(result.stderr);
      throw new Error(`SURVIVED: ${mutation.name}`);
    }
    caught += 1;
    console.log(`caught ${caught}/${mutations.length}: ${mutation.name}`);
  }

  assertRestored();
  const finalBaseline = run(['run', ...specs]);
  if (finalBaseline.status !== 0) {
    process.stderr.write(finalBaseline.stdout);
    process.stderr.write(finalBaseline.stderr);
    throw new Error('restored source does not pass its clean baseline');
  }
  console.log(`all ${caught} mutation(s) caught; sources restored byte for byte`);
} finally {
  restoreAll();
  assertRestored();
}
